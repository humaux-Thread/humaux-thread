//! `protocol::tests::page_budget` — G-M26-7 page budget and G-M26-8 cursor integrity for `protocol::page`.
//! Depends-on: crates=[humaux-application, humaux-domain, serde_json]; services=[]; env=[];
//!   modules=[application::signed_token, domain::error, domain::identity, protocol::mcp_catalog, protocol::page]
//! Called-by: [cargo-test]
//! Invariants: [2,392 seeded records mixing multibyte and escape-heavy text page through under both registry budgets
//!   with every page at most its budget and the cap, valid JSON, in order with no gap or duplicate, a truthful
//!   `omitted`, and cursor and `omitted` in both channels; a body over the cap is continued byte-exactly; a cursor
//!   from a tampered token, another principal, another op, other args, an expired window or an unrelated key is
//!   rejected with one and the same error, and one signed by the previous key is accepted]
//! Spec: §33.4; §33.5
//!
//! M26 D7 / D8. Records and key bytes come from a seeded SplitMix64, so a failure replays exactly. The renderer under
//! test keeps bodies in the text channel and ids in `structuredContent`, and calls `PageMeta::stamp` for the paging
//! fields; the pager is given nothing else to work with.

use humaux_application::signed_token::TokenKeys;
use humaux_domain::{error::ErrorCode, identity::PrincipalId};
use humaux_protocol::mcp_catalog::CanonicalCatalog;
use humaux_protocol::page::{
    Binding, Budget, Cursor, Entry, PageMeta, PageRecord, Pager, Position,
};
use serde_json::{Map, Value, json};

/// Cursor TTL the tests use (M26 D7: 900 s) and the clock they run on.
const TTL: i64 = 900;
const NOW: i64 = 1_790_000_000;
const SNAPSHOT: &str = "snapshot-1";
const PRINCIPAL: &str = "018f0000-0000-7000-8000-000000000001";
const OTHER_PRINCIPAL: &str = "018f0000-0000-7000-8000-000000000002";
/// The two budgets the registry carries today (8 KiB and 24 KiB); `budgets_come_from_the_registry` pins them.
const OPS: [&str; 2] = ["remember.put", "memory.get"];
/// Larger than the hard cap, for renderers that can never fit.
const OVERSIZE: usize = 100_000;

/// Text pieces covering CJK, emoji (including ZWJ and flag sequences), combining marks, quotes, backslashes, control
/// characters, `</script>` and the JSON-legal line separators.
const FRAGMENTS: &[&str] = &[
    "plain ascii words",
    "中文字符与标点，测试",
    "日本語のテキスト",
    "한국어 텍스트",
    "emoji 😀🚀👩‍👩‍👧‍👦🏳️‍🌈",
    "combining e\u{301} a\u{308}\u{323} n\u{303}",
    "stacked z\u{356}\u{316}\u{34f}",
    "quote \" backslash \\ slash /",
    "tab\tnewline\ncarriage\rreturn",
    "ctl \u{0}\u{1}\u{1f}\u{7f}",
    "</script><!-- --> ]]>",
    "sep \u{2028}\u{2029} end",
    "RTL עברית العربية",
    "{\"nested\":[1,2,3],\"k\":\"v\"}",
];

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).expect("bound fits u64");
        usize::try_from(self.draw() % bound).expect("value below a usize bound")
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Rec {
    id: u32,
    title: String,
    body: String,
}

impl PageRecord for Rec {
    fn resume_key(&self) -> String {
        format!("{:08}", self.id)
    }

    fn body(&self) -> &str {
        &self.body
    }
}

fn prose(rng: &mut Rng, max_parts: usize) -> String {
    let parts = 1 + rng.below(max_parts);
    let mut out = String::new();
    for n in 0..parts {
        if n > 0 {
            out.push(' ');
        }
        out.push_str(FRAGMENTS[rng.below(FRAGMENTS.len())]);
    }
    out
}

/// `count` records in key order; every 97th has a body of several KiB.
fn corpus(count: usize, seed: u64) -> Vec<Rec> {
    let mut rng = Rng(seed);
    let mut records = Vec::with_capacity(count);
    for id in 0..count {
        let title = prose(&mut rng, 3);
        let body = prose(&mut rng, if id.is_multiple_of(97) { 120 } else { 24 });
        records.push(Rec {
            id: u32::try_from(id).expect("id fits u32"),
            title,
            body,
        });
    }
    records
}

/// A body of more than twice `cap` bytes.
fn oversized_body(cap: usize) -> String {
    let mut body = String::new();
    let mut n = 0;
    while body.len() <= 2 * cap + 1000 {
        body.push_str(FRAGMENTS[n % FRAGMENTS.len()]);
        body.push(' ');
        n += 1;
    }
    body
}

/// The renderer an owner would write (M26 D8): one JSON line per entry in the text channel (bodies only there), ids
/// and the paging fields in `structuredContent`, the paging fields stamped into both.
fn render(entries: &[Entry<'_, Rec>], meta: &PageMeta) -> Value {
    let mut text = String::new();
    let mut ids = Vec::new();
    for entry in entries {
        let item =
            json!({ "id": entry.record.id, "title": entry.record.title, "body": entry.body });
        text.push_str(&item.to_string());
        text.push('\n');
        ids.push(entry.record.id);
    }
    let mut structured = Map::new();
    structured.insert("ids".to_owned(), json!(ids));
    meta.stamp(&mut text, &mut structured);
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured,
        "_meta": { "source": "page_budget" },
    })
}

/// A renderer whose output can never fit any budget.
fn render_oversize(_entries: &[Entry<'_, Rec>], _meta: &PageMeta) -> Value {
    json!({ "pad": "x".repeat(OVERSIZE) })
}

fn key_bytes(seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..4).flat_map(|_| rng.draw().to_le_bytes()).collect()
}

fn token_keys(current: u64, previous: Option<u64>) -> TokenKeys {
    TokenKeys::new(key_bytes(current), previous.map(key_bytes)).expect("valid test keys")
}

fn bind(principal: &str, op: &str, args: &Value) -> Binding {
    Binding::new(PrincipalId::parse(principal).expect("principal"), op, args)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(token: &str) -> Vec<u8> {
    (0..token.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&token[at..at + 2], 16).expect("hex"))
        .collect()
}

/// Replaces `from` with `to` inside the signed bytes of `token` and leaves the kid and MAC untouched.
fn swap_field(token: &str, from: &str, to: &str) -> String {
    let signed = String::from_utf8(unhex(token)).expect("signed token is utf-8");
    assert!(signed.contains(from), "the field to swap is in the payload");
    hex(signed.replacen(from, to, 1).as_bytes())
}

/// The same token with its last hex digit changed: one byte of the MAC differs.
fn flip_last_digit(token: &str) -> String {
    let (head, last) = token.split_at(token.len() - 1);
    let flipped = if last == "0" { "1" } else { "0" };
    format!("{head}{flipped}")
}

/// One op's budget, the catalog numbers the test measures against, and the signing material.
struct Rig {
    budget: Budget,
    op_budget: usize,
    cap: usize,
    keys: TokenKeys,
    binding: Binding,
}

impl Rig {
    fn new(op: &str) -> Self {
        let catalog = CanonicalCatalog::load().expect("catalog loads");
        Self {
            budget: Budget::for_op(&catalog, op).expect("op is in the registry"),
            op_budget: usize::try_from(catalog.operations()[op].budget_bytes).expect("budget"),
            cap: usize::try_from(catalog.budget_cap_bytes()).expect("cap"),
            keys: token_keys(1, None),
            binding: bind(PRINCIPAL, op, &json!({ "query": "everything" })),
        }
    }

    fn pager(&self) -> Pager<'_> {
        Pager::new(self.budget, &self.keys, &self.binding, SNAPSHOT, NOW, TTL)
    }
}

/// What a page says about itself, read back from its serialized bytes.
struct Seen {
    items: Vec<Value>,
    omitted: usize,
    complete: bool,
    next: Option<String>,
    body: Option<String>,
}

/// The value of the footer line `name: value` in the text channel.
fn footer<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
}

/// Reads both channels and asserts they agree on every paging field (D7/D8).
fn read_page(page: &Value) -> Seen {
    let text = page["content"][0]["text"]
        .as_str()
        .expect("the page carries a text channel");
    let structured = &page["structuredContent"];
    let items: Vec<Value> = text
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| serde_json::from_str(line).expect("item line is JSON"))
        .collect();
    let omitted: usize = footer(text, "omitted")
        .expect("omitted in the text channel")
        .parse()
        .expect("omitted is a number");
    assert_eq!(
        structured["omitted"].as_u64(),
        Some(u64::try_from(omitted).expect("omitted fits u64")),
        "omitted differs between the channels"
    );
    let complete = footer(text, "body_complete") == Some("true");
    assert_eq!(structured["body_complete"].as_bool(), Some(complete));
    let next = footer(text, "next_cursor").map(str::to_owned);
    let body = footer(text, "body_cursor").map(str::to_owned);
    assert_eq!(structured["next_cursor"].as_str().map(str::to_owned), next);
    assert_eq!(structured["body_cursor"].as_str().map(str::to_owned), body);
    Seen {
        items,
        omitted,
        complete,
        next,
        body,
    }
}

#[derive(Default)]
struct Walk {
    rebuilt: Vec<Rec>,
    pages: usize,
    split_pages: usize,
    max_bytes: usize,
}

/// Pages through all of `records` under `op`'s budget, the way a client follows cursors, asserting on every page.
fn page_through(records: &[Rec], op: &str) -> Walk {
    let rig = Rig::new(op);
    let pager = rig.pager();
    let mut walk = Walk::default();
    let (mut start, mut offset) = (0usize, 0usize);
    let mut open_body = false;
    loop {
        let out = pager
            .page(&records[start..], offset, render)
            .expect("a page");
        let bytes = out.json.len();
        assert!(
            bytes <= rig.op_budget && bytes <= rig.cap,
            "page {} is {bytes} bytes: budget {}, cap {}",
            walk.pages,
            rig.op_budget,
            rig.cap
        );
        let again: Value =
            serde_json::from_slice(&out.json).expect("the page bytes are valid JSON");
        assert_eq!(
            again, out.result,
            "the bytes are the result's serialization"
        );
        let seen = read_page(&again);

        let returned = seen.items.len();
        assert!(
            returned > 0,
            "records were supplied, so the page returns some"
        );
        assert_eq!(
            seen.omitted,
            (records.len() - start) - returned,
            "omitted on page {}",
            walk.pages
        );
        assert_eq!(
            seen.next.is_some(),
            seen.omitted > 0,
            "next_cursor iff omitted"
        );
        assert_eq!(
            seen.body.is_some(),
            !seen.complete,
            "body_cursor iff unfinished"
        );
        if !seen.complete {
            assert_eq!(returned, 1, "only the first record of a page is ever split");
            walk.split_pages += 1;
        }
        for (n, item) in seen.items.iter().enumerate() {
            let id = u32::try_from(item["id"].as_u64().expect("id")).expect("id");
            let title = item["title"].as_str().expect("title");
            let body = item["body"].as_str().expect("body");
            if n == 0 && open_body {
                let last = walk.rebuilt.last_mut().expect("a record to continue");
                assert_eq!((last.id, last.title.as_str()), (id, title));
                last.body.push_str(body);
            } else {
                walk.rebuilt.push(Rec {
                    id,
                    title: title.to_owned(),
                    body: body.to_owned(),
                });
            }
        }
        open_body = !seen.complete;
        walk.pages += 1;
        walk.max_bytes = walk.max_bytes.max(bytes);
        assert!(walk.pages < 10_000, "paging does not terminate");

        let following = if seen.complete { seen.next } else { seen.body };
        let Some(token) = following else {
            break;
        };
        let cursor = Cursor::open(&rig.keys, &token, &rig.binding, NOW).expect("own cursor opens");
        assert_eq!(cursor.snapshot, SNAPSHOT);
        (start, offset) = match cursor.position {
            Position::Record { resume_key } => {
                (records.partition_point(|r| r.resume_key() <= resume_key), 0)
            }
            Position::Body {
                resume_key,
                byte_offset,
            } => (
                records.partition_point(|r| r.resume_key() < resume_key),
                byte_offset,
            ),
        };
    }
    walk
}

fn assert_same(rebuilt: &[Rec], records: &[Rec]) {
    assert_eq!(rebuilt.len(), records.len(), "record count after paging");
    if let Some(at) = rebuilt.iter().zip(records).position(|(a, b)| a != b) {
        panic!(
            "record {at} differs after paging: id {} vs {}",
            rebuilt[at].id, records[at].id
        );
    }
}

#[test]
fn budgets_come_from_the_registry() {
    let catalog = CanonicalCatalog::load().expect("catalog loads");
    assert_eq!(catalog.budget_cap_bytes(), 49152);
    assert_eq!(Budget::for_op(&catalog, OPS[0]).unwrap().limit(), 8192);
    assert_eq!(Budget::for_op(&catalog, OPS[1]).unwrap().limit(), 24576);
    assert_eq!(
        Budget::for_op(&catalog, "no.such.op"),
        Err(ErrorCode::Internal)
    );
}

/// G-M26-7: 2,392 multibyte and escape-heavy records, under each budget.
#[test]
fn g_m26_7_corpus_pages_fit_parse_and_reassemble() {
    let records = corpus(2392, 26);
    assert!(
        records.iter().any(|r| r.body.contains('😀')),
        "emoji in the corpus"
    );
    assert!(
        records.iter().any(|r| r.body.contains('中')),
        "CJK in the corpus"
    );
    assert!(
        records.iter().any(|r| r.body.contains("</script>")),
        "script close in the corpus"
    );
    assert!(
        records.iter().any(|r| r.body.contains('\u{0}')),
        "control chars in the corpus"
    );
    for op in OPS {
        let walk = page_through(&records, op);
        assert_same(&walk.rebuilt, &records);
        assert!(walk.pages > 1, "{op}: the corpus needs several pages");
    }
}

/// G-M26-7: one body over the cap is continued byte-exactly and every page still fits.
#[test]
fn g_m26_7_body_over_the_cap_is_continued_byte_exactly() {
    for op in OPS {
        let cap = Rig::new(op).cap;
        let mut records = corpus(3, 7);
        records[1].body = oversized_body(cap);
        let walk = page_through(&records, op);
        assert_same(&walk.rebuilt, &records);
        assert_eq!(
            walk.rebuilt[1].body, records[1].body,
            "{op}: body is byte-exact"
        );
        assert!(walk.split_pages >= 2, "{op}: the body takes several pages");
        assert!(walk.max_bytes <= cap);
    }
}

#[test]
fn an_empty_supply_is_a_page_without_a_cursor() {
    let rig = Rig::new(OPS[1]);
    let out = rig.pager().page(&[], 0, render).expect("empty page");
    let seen = read_page(&out.result);
    assert!(seen.items.is_empty() && seen.complete);
    assert_eq!((seen.omitted, seen.next, seen.body), (0, None, None));
}

#[test]
fn a_page_that_cannot_fit_is_an_error_not_a_loop() {
    let rig = Rig::new(OPS[0]);
    let pager = rig.pager();
    let rec = Rec {
        id: 1,
        title: "t".to_owned(),
        body: "body".to_owned(),
    };
    // Even the empty page does not fit.
    let empty = pager.page(&[], 0, render_oversize);
    assert_eq!(empty.unwrap_err(), ErrorCode::Internal);
    // The record cannot fit even with its body cut to nothing.
    let fat = Rec {
        title: "x".repeat(OVERSIZE),
        ..rec.clone()
    };
    let fat_page = pager.page(&[fat], 0, render);
    assert_eq!(fat_page.unwrap_err(), ErrorCode::Internal);
    // A body offset inside a multibyte character is not a cursor this pager minted.
    let wide = Rec {
        body: "中文".to_owned(),
        ..rec
    };
    let misaligned = pager.page(&[wide], 1, render);
    assert_eq!(misaligned.unwrap_err(), ErrorCode::InvalidInput);
}

fn sample_cursor() -> Cursor {
    Cursor {
        snapshot: "snap-7".to_owned(),
        position: Position::Body {
            resume_key: "00000042".to_owned(),
            byte_offset: 1234,
        },
    }
}

#[test]
fn a_cursor_round_trips_and_the_cursor_argument_is_not_part_of_the_binding() {
    let keys = token_keys(1, None);
    let first_call = json!({ "query": "needle", "n": 3 });
    let minted_for = bind(PRINCIPAL, "memory.get", &first_call);
    let token = sample_cursor().sign(&keys, &minted_for, NOW + TTL);
    // The follow-up call carries the cursor and the same other arguments, in any member order.
    let follow_up = json!({ "n": 3, "cursor": token, "query": "needle" });
    let presented = bind(PRINCIPAL, "memory.get", &follow_up);
    assert_eq!(
        Cursor::open(&keys, &token, &presented, NOW),
        Ok(sample_cursor())
    );
    let record = Cursor {
        snapshot: "s".to_owned(),
        position: Position::Record {
            resume_key: "k".to_owned(),
        },
    };
    let record_token = record.sign(&keys, &minted_for, NOW + TTL);
    assert_eq!(
        Cursor::open(&keys, &record_token, &minted_for, NOW),
        Ok(record)
    );
}

/// G-M26-8: every failing leg is the same error; the tampered-field case keeps a valid kid and MAC on swapped bytes.
#[test]
fn g_m26_8_every_rejection_is_the_same_error() {
    let keys = token_keys(1, None);
    let args = json!({ "query": "needle" });
    let bound = bind(PRINCIPAL, "memory.get", &args);
    let token = sample_cursor().sign(&keys, &bound, NOW + TTL);
    let cases = [
        ("flipped byte", flip_last_digit(&token), bound.clone(), NOW),
        (
            "swapped field",
            swap_field(&token, PRINCIPAL, OTHER_PRINCIPAL),
            bind(OTHER_PRINCIPAL, "memory.get", &args),
            NOW,
        ),
        (
            "other principal",
            token.clone(),
            bind(OTHER_PRINCIPAL, "memory.get", &args),
            NOW,
        ),
        (
            "other op",
            token.clone(),
            bind(PRINCIPAL, "remember.put", &args),
            NOW,
        ),
        (
            "other args",
            token.clone(),
            bind(PRINCIPAL, "memory.get", &json!({ "query": "other" })),
            NOW,
        ),
        ("expired", token.clone(), bound.clone(), NOW + TTL),
        (
            "unrelated key",
            sample_cursor().sign(&token_keys(9, None), &bound, NOW + TTL),
            bound.clone(),
            NOW,
        ),
        ("garbage", "not-a-cursor".to_owned(), bound.clone(), NOW),
        ("empty", String::new(), bound.clone(), NOW),
    ];
    for (name, presented, expected, now) in cases {
        assert_eq!(
            Cursor::open(&keys, &presented, &expected, now),
            Err(ErrorCode::InvalidInput),
            "{name}"
        );
    }
    // The last second of the window is still inside it.
    assert!(Cursor::open(&keys, &token, &bound, NOW + TTL - 1).is_ok());
}

/// G-M26-8: a cursor signed with the previous key opens while the rotation window is open, and not after.
#[test]
fn g_m26_8_the_previous_key_is_accepted() {
    let bound = bind(PRINCIPAL, "memory.get", &json!({}));
    let old_keys = token_keys(1, None);
    let token = sample_cursor().sign(&old_keys, &bound, NOW + TTL);
    let rotated = token_keys(2, Some(1));
    assert_eq!(
        Cursor::open(&rotated, &token, &bound, NOW),
        Ok(sample_cursor())
    );
    let closed = token_keys(2, None);
    assert_eq!(
        Cursor::open(&closed, &token, &bound, NOW),
        Err(ErrorCode::InvalidInput)
    );
}
