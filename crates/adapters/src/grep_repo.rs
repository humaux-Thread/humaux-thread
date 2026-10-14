//! `adapters::grep_repo` — ADR-0069 `memory.grep`: a literal, case-insensitive substring search over the caller's
//!   authorized memories, one hit per matching line with ±1 line of context, true totals and a keyset page, all in one
//!   snapshot.
//! Depends-on: crates=[humaux-domain, sqlx]; services=[PostgreSQL(role_gateway) r=[private.memory_records]]; env=[];
//!   modules=[adapters::context_repo, adapters::postgres, adapters::read_materialize, domain::error, domain::identity,
//!   domain::ids]
//! Called-by: [gateway::memory, tests]
//! Invariants: [candidates, the final gate, the totals, the page and the context bodies come from ONE REPEATABLE READ
//!   READ ONLY transaction; what a grep may count or show is exactly what the shared final gate admits
//!   (`read_materialize::final_memory_ids_about_in_txn`: can_read, lifecycle, secret backing, tombstoned Evidence on
//!   any stream), never a second predicate; a cancelled statement is a refusal, never a partial total]
//! Spec: Baseline §33; §33.10; §22.1; §52; ADR-0069

use std::time::Duration;

use humaux_domain::error::ErrorCode;
use humaux_domain::identity::AuthorizationScope;
use humaux_domain::ids::WorkspaceId;
use sqlx::Row;
use sqlx::types::Uuid;

use crate::context_repo::{ENUMERATION_SCOPE, set_authorization_local};
use crate::postgres::RuntimeDbPool;
use crate::read_materialize::{Lifecycle, final_memory_ids_about_in_txn};

/// ADR-0069 D-B: the longest pattern accepted, in Unicode scalars (the contract's `maxLength`).
pub const MAX_PATTERN_CHARS: usize = 512;

/// ADR-0069 D-C: the text a grep searches, and the text its line numbers and context come from — a bare-string
/// content (the `memory.correct` shape) whole, otherwise the title, key claim and evidence excerpt joined by line
/// breaks (`concat_ws` skips an absent field). `{t}` = the `memory_records` alias. Key names, other keys and JSON
/// escaping are never searched.
const MEMORY_TEXT: &str = "(CASE jsonb_typeof({t}.content) WHEN 'string' THEN {t}.content #>> '{}' \
     ELSE concat_ws(E'\\n', {t}.content ->> 'title', {t}.content ->> 'key_claim', \
                    {t}.content ->> 'evidence_excerpt') END)";

fn memory_text(alias: &str) -> String {
    MEMORY_TEXT.replace("{t}", alias)
}

/// ADR-0069 D-B (research R-41): `literal` as an `ILIKE … ESCAPE '!'` operand that matches it as a substring — `!`,
/// `%` and `_` escaped, so none of them is a wildcard.
pub fn literal_like_pattern(literal: &str) -> String {
    let escaped = literal
        .replace('!', "!!")
        .replace('%', "!%")
        .replace('_', "!_");
    format!("%{escaped}%")
}

/// One validated `memory.grep` request.
#[derive(Debug, Clone)]
pub struct GrepQuery {
    pattern: String,
    lifecycle: Lifecycle,
    page_size: u16,
    after: Option<(Uuid, i64)>,
    budget: Option<Duration>,
}

impl GrepQuery {
    /// `after` is the last `(memory_id, line_no)` of the previous page (from a verified cursor); `budget` overrides the
    /// role's statement timeout for this read (`None` = the pool's §78 setting).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidInput`] for an empty pattern, one longer than [`MAX_PATTERN_CHARS`], one containing a line
    /// break (a hit is one line, ADR-0069 D-B), or a page size outside 1..=100.
    pub fn new(
        pattern: &str,
        lifecycle: Lifecycle,
        page_size: u16,
        after: Option<(Uuid, i64)>,
        budget: Option<Duration>,
    ) -> Result<Self, ErrorCode> {
        if pattern.is_empty()
            || pattern.chars().count() > MAX_PATTERN_CHARS
            || pattern.contains(['\n', '\r'])
            || !(1..=100).contains(&page_size)
        {
            return Err(ErrorCode::InvalidInput);
        }
        Ok(Self {
            pattern: pattern.to_owned(),
            lifecycle,
            page_size,
            after,
            budget,
        })
    }
}

/// One matching line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrepHit {
    /// The memory the line belongs to.
    pub memory_id: Uuid,
    /// 1-based, over [`MEMORY_TEXT`]'s lines.
    pub line_no: i64,
    /// The matching line.
    pub line: String,
    /// The line before it, `None` on the first line.
    pub before: Option<String>,
    /// The line after it, `None` on the last line.
    pub after: Option<String>,
    /// Every matching line of this memory in the whole result, not only this page's.
    pub memory_matching_lines: i64,
    /// `active` or `superseded`.
    pub status: String,
    /// Whether the memory is archived (only with an `archive` selection that admits archived rows).
    pub archived: bool,
}

/// One keyset page with the totals of the same snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrepPage {
    /// This page's hits, ordered by `(memory_id, line_no)`.
    pub items: Vec<GrepHit>,
    /// Every matching line in the caller's view, in this snapshot.
    pub total_matching_lines: i64,
    /// The memories those lines belong to.
    pub total_memories: i64,
    /// Whether hits follow this page.
    pub has_more: bool,
}

impl GrepPage {
    /// The keyset position after this page's last hit, `None` when nothing follows.
    pub fn next_after(&self) -> Option<(Uuid, i64)> {
        if !self.has_more {
            return None;
        }
        self.items.last().map(|hit| (hit.memory_id, hit.line_no))
    }
}

/// ADR-0069 D-D: a statement cancelled by the budget (`57014`) means the totals cannot be vouched for; anything else
/// is an internal read failure.
fn read_error(error: &sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("57014") => {
            ErrorCode::CannotEstablishCompleteness
        }
        _ => ErrorCode::Internal,
    }
}

/// The hits over the authorized ids: totals, the keyset page (`limit` + 1 rows to detect more) and each page row's
/// per-memory count. `$1` tenant, `$2` authorized ids, `$3` pattern, `$4`/`$5` keyset position, `$6` row limit.
fn hits_sql() -> String {
    format!(
        "WITH docs AS NOT MATERIALIZED ( \
           SELECT m.memory_id, {text} AS body FROM private.memory_records m \
            WHERE m.tenant_id = $1 AND m.memory_id = ANY($2)), \
         hits AS MATERIALIZED ( \
           SELECT d.memory_id, l.line_no FROM docs d \
            CROSS JOIN LATERAL unnest(string_to_array(d.body, E'\\n')) WITH ORDINALITY AS l(line_text, line_no) \
            WHERE l.line_text ILIKE $3 ESCAPE '!'), \
         page AS ( \
           SELECT h.memory_id, h.line_no FROM hits h \
            WHERE $4::uuid IS NULL OR (h.memory_id, h.line_no) > ($4::uuid, $5::bigint) \
            ORDER BY h.memory_id, h.line_no LIMIT $6) \
         SELECT (SELECT count(*) FROM hits) AS total_lines, \
                (SELECT count(DISTINCT memory_id) FROM hits) AS total_memories, \
                COALESCE((SELECT array_agg(p.memory_id ORDER BY p.memory_id, p.line_no) FROM page p), \
                         '{{}}'::uuid[]) AS page_memories, \
                COALESCE((SELECT array_agg(p.line_no ORDER BY p.memory_id, p.line_no) FROM page p), \
                         '{{}}'::bigint[]) AS page_lines, \
                COALESCE((SELECT array_agg((SELECT count(*) FROM hits h2 WHERE h2.memory_id = p.memory_id) \
                                           ORDER BY p.memory_id, p.line_no) FROM page p), \
                         '{{}}'::bigint[]) AS page_counts",
        text = memory_text("m"),
    )
}

/// The memories a grep may report: the enumeration scope and the literal over the whole text, then the shared final
/// gate under the request's lifecycle selection. Sorted for the `ANY($2)` bind.
async fn admitted_candidates(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authorization: &AuthorizationScope,
    workspace: WorkspaceId,
    query: &GrepQuery,
    like: &str,
) -> Result<Vec<Uuid>, ErrorCode> {
    // $1 tenant, $2 workspace, $3 pattern.
    let candidates_sql = format!(
        "SELECT memory_id FROM {ENUMERATION_SCOPE} AND {} ILIKE $3 ESCAPE '!'",
        memory_text("memory_records"),
    );
    let candidates: Vec<Uuid> = sqlx::query_scalar(&candidates_sql)
        .bind(authorization.tenant_id().0)
        .bind(workspace.0)
        .bind(like)
        .fetch_all(&mut **txn)
        .await
        .map_err(|e| read_error(&e))?;
    let mut admitted =
        final_memory_ids_about_in_txn(txn, authorization, &candidates, query.lifecycle, &[], None)
            .await?;
    admitted.sort_unstable();
    Ok(admitted)
}

/// ADR-0069: one `memory.grep` page over `workspace`.
///
/// # Errors
/// [`ErrorCode::CannotEstablishCompleteness`] when one of this module's statements exceeds the query budget;
/// [`ErrorCode::DependencyUnavailable`] when the shared final gate's does (its own mapping); [`ErrorCode::Internal`]
/// for any other read failure.
pub async fn grep(
    pool: &RuntimeDbPool,
    authorization: &AuthorizationScope,
    workspace: WorkspaceId,
    query: &GrepQuery,
) -> Result<GrepPage, ErrorCode> {
    let tenant = authorization.tenant_id().0;
    // dep: PostgreSQL(role_gateway) — transaction entry for `grep`
    let mut txn = pool.pool().begin().await.map_err(|e| read_error(&e))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *txn)
        .await
        .map_err(|e| read_error(&e))?;
    set_authorization_local(&mut txn, authorization).await?;
    if let Some(budget) = query.budget {
        // A bound integer, not caller text: `SET` takes no parameters.
        sqlx::query(&format!(
            "SET LOCAL statement_timeout = {}",
            budget.as_millis().max(1)
        ))
        .execute(&mut *txn)
        .await
        .map_err(|e| read_error(&e))?;
    }
    let like = literal_like_pattern(&query.pattern);
    let authorized = admitted_candidates(&mut txn, authorization, workspace, query, &like).await?;

    let (after_memory, after_line) = query.after.unzip();
    let row = sqlx::query(&hits_sql())
        .bind(tenant)
        .bind(&authorized)
        .bind(&like)
        .bind(after_memory)
        .bind(after_line)
        .bind(i64::from(query.page_size) + 1)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| read_error(&e))?;
    let decode = |e: sqlx::Error| read_error(&e);
    let total_matching_lines: i64 = row.try_get("total_lines").map_err(decode)?;
    let total_memories: i64 = row.try_get("total_memories").map_err(decode)?;
    let mut page_memories: Vec<Uuid> = row.try_get("page_memories").map_err(decode)?;
    let mut page_lines: Vec<i64> = row.try_get("page_lines").map_err(decode)?;
    let mut page_counts: Vec<i64> = row.try_get("page_counts").map_err(decode)?;
    let has_more = page_memories.len() > usize::from(query.page_size);
    page_memories.truncate(usize::from(query.page_size));
    page_lines.truncate(usize::from(query.page_size));
    page_counts.truncate(usize::from(query.page_size));

    let bodies = sqlx::query(&format!(
        "SELECT m.memory_id, {} AS body, m.status, m.archived_at IS NOT NULL AS archived \
           FROM private.memory_records m WHERE m.tenant_id = $1 AND m.memory_id = ANY($2)",
        memory_text("m"),
    ))
    .bind(tenant)
    .bind(&page_memories)
    .fetch_all(&mut *txn)
    .await
    .map_err(|e| read_error(&e))?;
    let mut by_memory = std::collections::HashMap::with_capacity(bodies.len());
    for row in bodies {
        let id: Uuid = row.try_get("memory_id").map_err(decode)?;
        let body: String = row.try_get("body").map_err(decode)?;
        let status: String = row.try_get("status").map_err(decode)?;
        let archived: bool = row.try_get("archived").map_err(decode)?;
        by_memory.insert(id, (body, status, archived));
    }
    txn.commit().await.map_err(|e| read_error(&e))?;

    let items = page_memories
        .into_iter()
        .zip(page_lines)
        .zip(page_counts)
        .map(|((memory_id, line_no), memory_matching_lines)| {
            let (body, status, archived) = by_memory.get(&memory_id).ok_or(ErrorCode::Internal)?;
            let (before, line, after) = context(body, line_no).ok_or(ErrorCode::Internal)?;
            Ok(GrepHit {
                memory_id,
                line_no,
                line,
                before,
                after,
                memory_matching_lines,
                status: status.clone(),
                archived: *archived,
            })
        })
        .collect::<Result<Vec<_>, ErrorCode>>()?;
    Ok(GrepPage {
        items,
        total_matching_lines,
        total_memories,
        has_more,
    })
}

/// ADR-0069 D-C: line `line_no` (1-based) of `body` with its neighbours, split exactly as `string_to_array(body,
/// E'\n')` splits (a `\r` stays on its line). `None` when the line does not exist.
fn context(body: &str, line_no: i64) -> Option<(Option<String>, String, Option<String>)> {
    let lines: Vec<&str> = body.split('\n').collect();
    let index = usize::try_from(line_no).ok()?.checked_sub(1)?;
    let line = (*lines.get(index)?).to_owned();
    let before = index
        .checked_sub(1)
        .and_then(|i| lines.get(i))
        .map(|l| (*l).to_owned());
    let after = lines.get(index + 1).map(|l| (*l).to_owned());
    Some((before, line, after))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-0069 D-B: `!`, `%` and `_` are escaped so each matches only itself. Fault: drop any one replace ⇒ red.
    #[test]
    fn literal_pattern_escapes_every_wildcard() {
        assert_eq!(literal_like_pattern("50%_off!"), "%50!%!_off!!%");
        assert_eq!(literal_like_pattern("plain"), "%plain%");
        assert_eq!(literal_like_pattern("中文::x"), "%中文::x%");
    }

    /// ADR-0069 D-B: a pattern is one non-empty line of at most 512 scalars; a page is 1..=100 rows.
    #[test]
    fn query_shape_is_validated() {
        let ok = |p: &str, n| GrepQuery::new(p, Lifecycle::CURRENT, n, None, None).is_ok();
        assert!(ok("x", 1) && ok(&"é".repeat(512), 100));
        assert!(!ok("", 10));
        assert!(!ok("a\nb", 10) && !ok("a\rb", 10));
        assert!(!ok(&"é".repeat(513), 10));
        assert!(!ok("x", 0) && !ok("x", 101));
    }

    /// ADR-0069 D-C: context at the first and last line and in the middle; a missing line is `None`.
    #[test]
    fn context_lines_follow_string_to_array() {
        let body = "one\ntwo\r\nthree";
        assert_eq!(
            context(body, 1),
            Some((None, "one".to_owned(), Some("two\r".to_owned())))
        );
        assert_eq!(
            context(body, 2),
            Some((
                Some("one".to_owned()),
                "two\r".to_owned(),
                Some("three".to_owned())
            ))
        );
        assert_eq!(
            context(body, 3),
            Some((Some("two\r".to_owned()), "three".to_owned(), None))
        );
        assert_eq!(context(body, 4), None);
        assert_eq!(context(body, 0), None);
    }
}
