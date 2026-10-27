//! `public-pool::admission::deid` — A3 de-identification over every surface plus the combined identifiability floor (D6', ADR-0090 D-C).
//! Depends-on: crates=[serde_json]; services=[]; env=[]; modules=[public-pool::completeness]
//! Called-by: [tests]
//! Invariants: [pure and deterministic: no I/O, no model, no clock; any hit on any surface rejects (D6'); a NotSupplied surface or an
//!   unchecked secret scan is NOT_RUN and never pass; a hit records detector, surface, char offset and length, never the matched text
//!   (ADR-0088 D-D)]
//! Spec: Baseline §12.6; §57.1; §78.2; ADR-0088 D-D; ADR-0090 D-C
//!
//! A3 inspects the twelve surfaces of ADR-0090 D-C: body, title, tags, entity aliases, code comments, paths, URL queries, quotes, edge
//! text, numbers, dates and attribution. Every detector below runs on every surface and one hit anywhere rejects. The caller (M20-11)
//! extracts the surfaces; an extractor that did not run is `NotSupplied` and makes the receipt NOT_RUN. The attribution is the literal
//! `contributor` and never `NotSupplied`; any other value is a hit.
//!
//! The detector set is closed (`Detector::ALL`); this table is checked against it by `tests/admission_deid.rs`.
//!
//! | id | what it flags |
//! |---|---|
//! | `email` | an address with a local part and a domain ending in an alphabetic TLD |
//! | `phone` | a `+` international number of 8-15 digits, or a CN mobile number (11 digits or 3-4-4 groups) |
//! | `cn_resident_id` | 18 characters with a valid birth date and the GB 11643 checksum |
//! | `payment_card` | 13-19 digits (single space or dash between groups) that pass the Luhn check |
//! | `ip_address` | an IPv4 or IPv6 address outside the documentation, loopback, private and unspecified ranges |
//! | `mac_address` | six hex pairs joined by colons or dashes |
//! | `user_home_path` | a user-home path under /Users, /home, a Windows drive (any case), or a tilde-user prefix; the user segment may use any script (placeholder names exempt) |
//! | `url_query` | a URL whose query or fragment carries key=value, or a bare key=value on the url_queries surface |
//! | `url_userinfo` | a URL authority that carries a user or credentials |
//! | `person_name_en` | a dictionary given name, or an honorific followed by a capitalised word |
//! | `person_name_zh` | a name-context marker (including Mr, Ms, Dr, Prof) before, or a courtesy title after, a dictionary surname and one or two Han characters |
//! | `org_marker` | a legal-entity suffix next to a proper noun |
//! | `contract_marker` | a confidentiality, NDA, trade-secret or contract-number marker |
//! | `attribution` | an attribution value other than the literal contributor |
//! | `combined_identifiability` | at least `COMBINED_FLOOR` distinct quasi-identifier classes in one draft |
//! | `secret_scan` | the shared pinned secret scanner reported a hit |
//!
//! The quasi-identifier classes are a full calendar date, a place below country level, an organisation name, a job title, an age (including
//! a labelled `age: 34` or `年龄：34` field) and a gender word (including a `Gender: F` or `性别：` field). A software release date is not
//! a quasi-identifier: a date with a release word, a changelog or version word, a `v` plus digit or a semantic version within
//! `RELEASE_WINDOW` characters on the same line is skipped.

use crate::completeness::{GateState, RuleReceipt, UnitDraft, closed_set};
use serde_json::Value;
use std::sync::OnceLock;

/// Receipt version; changes whenever a detector, a dictionary or the floor changes (ADR-0090 D-C).
pub const A3_RULE_VERSION: &str = "M20-deid-1";

/// The only legal attribution value (ADR-0088 D-D).
pub const CONTRIBUTOR: &str = "contributor";

/// Distinct quasi-identifier classes at which a draft is rejected (D6' combined identifiability, U4 start value).
// ponytail: start value; E-M20-1 tunes it. Not a §78.1 business threshold because the design note names no number.
pub const COMBINED_FLOOR: usize = 2;

/// Characters on each side of a date, on the same line, searched for a release or version context.
const RELEASE_WINDOW: usize = 32;

closed_set! {
    /// The twelve surfaces A3 inspects, in the design note's order (D6').
    Surface {
        /// Unit body text.
        Body => "body",
        /// Unit title.
        Title => "title",
        /// Tags.
        Tags => "tags",
        /// Entity aliases.
        EntityAliases => "entity_aliases",
        /// Comments inside code.
        CodeComments => "code_comments",
        /// File and directory paths.
        Paths => "paths",
        /// URL query strings and fragments.
        UrlQueries => "url_queries",
        /// Quoted source text.
        Quotes => "quotes",
        /// Text carried on graph edges.
        EdgeText => "edge_text",
        /// Numeric literals.
        Numbers => "numbers",
        /// Dates.
        Dates => "dates",
        /// The attribution value.
        Attribution => "attribution",
    }
}

closed_set! {
    /// The closed detector set of A3; ids are the receipt vocabulary (D6', §78.2).
    Detector {
        /// E-mail address.
        Email => "email",
        /// International or CN mobile phone number.
        Phone => "phone",
        /// CN resident ID with checksum.
        CnResidentId => "cn_resident_id",
        /// Payment card number passing Luhn.
        PaymentCard => "payment_card",
        /// Non-documentation IPv4 or IPv6 address.
        IpAddress => "ip_address",
        /// MAC address.
        MacAddress => "mac_address",
        /// User-home path.
        UserHomePath => "user_home_path",
        /// URL query or fragment carrying key=value.
        UrlQuery => "url_query",
        /// Credentials or user in a URL authority.
        UrlUserinfo => "url_userinfo",
        /// English person name.
        PersonNameEn => "person_name_en",
        /// Chinese person name in a name context.
        PersonNameZh => "person_name_zh",
        /// Legal-entity suffix next to a proper noun.
        OrgMarker => "org_marker",
        /// Confidentiality, NDA, trade-secret or contract marker.
        ContractMarker => "contract_marker",
        /// Attribution other than the literal.
        Attribution => "attribution",
        /// Quasi-identifier classes at or above the floor.
        CombinedIdentifiability => "combined_identifiability",
        /// The shared secret scanner reported a hit.
        Secret => "secret_scan",
    }
}

/// One located hit. It carries no matched text, so a receipt can never copy PII (ADR-0088 D-D, D6').
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    /// Detector that fired.
    pub detector: Detector,
    /// Surface it fired on.
    pub surface: Surface,
    /// Offset in chars from the start of the surface text, whose items are joined by one separator char.
    pub char_offset: usize,
    /// Length in chars.
    pub len: usize,
}

impl Hit {
    /// Receipt reason `detector@surface:offset+len`; never the matched text.
    pub fn reason(&self) -> String {
        format!(
            "{}@{}:{}+{}",
            self.detector.as_str(),
            self.surface.as_str(),
            self.char_offset,
            self.len
        )
    }
}

/// What the caller supplied for one surface (D6').
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceText {
    /// The extractor ran; the list may be empty.
    Supplied(Vec<String>),
    /// The extractor did not run; the receipt can only be NOT_RUN.
    NotSupplied,
}

/// The twelve surfaces of one draft, extracted by the caller (M20-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surfaces {
    /// Unit body text.
    pub body: SurfaceText,
    /// Unit title.
    pub title: SurfaceText,
    /// Tags.
    pub tags: SurfaceText,
    /// Entity aliases.
    pub entity_aliases: SurfaceText,
    /// Comments inside code.
    pub code_comments: SurfaceText,
    /// File and directory paths.
    pub paths: SurfaceText,
    /// URL query strings and fragments.
    pub url_queries: SurfaceText,
    /// Quoted source text.
    pub quotes: SurfaceText,
    /// Text carried on graph edges.
    pub edge_text: SurfaceText,
    /// Numeric literals.
    pub numbers: SurfaceText,
    /// Dates.
    pub dates: SurfaceText,
    /// The attribution value; never `NotSupplied`, and anything but [`CONTRIBUTOR`] is a hit (ADR-0088 D-D).
    pub attribution: String,
}

impl Default for Surfaces {
    /// Nothing supplied: eleven `NotSupplied` surfaces and the literal attribution.
    fn default() -> Self {
        Self {
            body: SurfaceText::NotSupplied,
            title: SurfaceText::NotSupplied,
            tags: SurfaceText::NotSupplied,
            entity_aliases: SurfaceText::NotSupplied,
            code_comments: SurfaceText::NotSupplied,
            paths: SurfaceText::NotSupplied,
            url_queries: SurfaceText::NotSupplied,
            quotes: SurfaceText::NotSupplied,
            edge_text: SurfaceText::NotSupplied,
            numbers: SurfaceText::NotSupplied,
            dates: SurfaceText::NotSupplied,
            attribution: CONTRIBUTOR.to_owned(),
        }
    }
}

impl Surfaces {
    /// What a [`UnitDraft`] carries by itself: every string in its field values as `body` and every JSON number as `numbers`.
    /// The other nine surfaces stay `NotSupplied` because a draft has no title, tags, aliases, comments, paths, queries, quotes,
    /// edge text or dates of its own (D6').
    pub fn from_draft(draft: &UnitDraft) -> Self {
        let mut strings = Vec::new();
        let mut numbers = Vec::new();
        for field in draft.fields.values() {
            if let Some(value) = &field.value {
                collect(value, &mut strings, &mut numbers);
            }
        }
        Self {
            body: SurfaceText::Supplied(strings),
            numbers: SurfaceText::Supplied(numbers),
            ..Self::default()
        }
    }

    fn entries(&self) -> [(Surface, &SurfaceText); 11] {
        [
            (Surface::Body, &self.body),
            (Surface::Title, &self.title),
            (Surface::Tags, &self.tags),
            (Surface::EntityAliases, &self.entity_aliases),
            (Surface::CodeComments, &self.code_comments),
            (Surface::Paths, &self.paths),
            (Surface::UrlQueries, &self.url_queries),
            (Surface::Quotes, &self.quotes),
            (Surface::EdgeText, &self.edge_text),
            (Surface::Numbers, &self.numbers),
            (Surface::Dates, &self.dates),
        ]
    }

    fn all_supplied(&self) -> bool {
        self.entries()
            .iter()
            .all(|(_, text)| matches!(text, SurfaceText::Supplied(_)))
    }
}

fn collect(value: &Value, strings: &mut Vec<String>, numbers: &mut Vec<String>) {
    match value {
        Value::String(s) => strings.push(s.clone()),
        Value::Number(n) => numbers.push(n.to_string()),
        Value::Array(items) => items.iter().for_each(|v| collect(v, strings, numbers)),
        Value::Object(map) => {
            for (key, inner) in map {
                strings.push(key.clone());
                collect(inner, strings, numbers);
            }
        }
        Value::Null | Value::Bool(_) => {}
    }
}

/// Outcome of the shared pinned secret scan, mapped by the caller from `LocalSecretScanOutcome` (wiring is M20-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretScan {
    /// The scanner ran and found nothing; the digest binds the scanner's receipt.
    Clean {
        /// Digest of the scanner receipt; an empty digest counts as not run.
        receipt_digest: String,
    },
    /// The scanner reported a hit.
    Hit {
        /// Scanner rule id; `'static` so a scanner cannot smuggle matched text into a public receipt.
        rule_id: &'static str,
    },
    /// The scanner did not run.
    NotRun,
}

impl SecretScan {
    fn checked(&self) -> bool {
        matches!(self, Self::Clean { receipt_digest } if !receipt_digest.trim().is_empty())
    }
}

/// All A3 hits for a draft: the supplied surfaces, the draft's own field text, the attribution and the combined floor.
pub fn scan(draft: &UnitDraft, surfaces: &Surfaces) -> Vec<Hit> {
    let mut out = Vec::new();
    let mut quasi = Vec::new();
    let own = Surfaces::from_draft(draft);
    for part in [surfaces, &own] {
        for (surface, text) in part.entries() {
            if let SurfaceText::Supplied(items) = text {
                scan_surface(surface, items, &mut out, &mut quasi);
            }
        }
    }
    if surfaces.attribution != CONTRIBUTOR {
        let len = surfaces.attribution.chars().count();
        out.push(Hit {
            detector: Detector::Attribution,
            surface: Surface::Attribution,
            char_offset: 0,
            len,
        });
        let items = std::slice::from_ref(&surfaces.attribution);
        scan_surface(Surface::Attribution, items, &mut out, &mut quasi);
    }
    out.extend(combined(&quasi));
    let mut seen: Vec<Hit> = Vec::new();
    out.retain(|hit| {
        let fresh = !seen.contains(hit);
        if fresh {
            seen.push(*hit);
        }
        fresh
    });
    out
}

/// The A3 receipt: any hit is `Fail` with `detector@surface:offset+len` reasons; otherwise a `NotSupplied` surface or an unchecked
/// secret scan is `NotRun`; only a fully checked, clean draft is `Pass` (D6', ADR-0090 D-C, §57.1).
pub fn a3(draft: &UnitDraft, surfaces: &Surfaces, secrets: SecretScan) -> RuleReceipt {
    let mut reasons: Vec<String> = scan(draft, surfaces).iter().map(Hit::reason).collect();
    if let SecretScan::Hit { rule_id } = &secrets {
        reasons.push(format!("{}:{rule_id}", Detector::Secret.as_str()));
    }
    let state = if !reasons.is_empty() {
        GateState::Fail(reasons)
    } else if surfaces.all_supplied() && secrets.checked() {
        GateState::Pass
    } else {
        GateState::NotRun
    };
    RuleReceipt {
        rule: "A3",
        rule_version: A3_RULE_VERSION,
        state,
    }
}

type Span = (usize, usize);
type Found = (Detector, usize, usize);
type QuasiHit = (Quasi, Surface, usize, usize);

fn scan_surface(surface: Surface, items: &[String], out: &mut Vec<Hit>, quasi: &mut Vec<QuasiHit>) {
    let mut base = 0;
    for item in items {
        let c: Vec<char> = item.chars().collect();
        for (detector, start, len) in detect(&c) {
            out.push(Hit {
                detector,
                surface,
                char_offset: base + start,
                len,
            });
        }
        if surface == Surface::UrlQueries && has_key_value(&c) {
            out.push(Hit {
                detector: Detector::UrlQuery,
                surface,
                char_offset: base,
                len: c.len(),
            });
        }
        for (class, start, len) in quasi_hits(&c) {
            quasi.push((class, surface, base + start, len));
        }
        base += c.len() + 1;
    }
}

fn detect(c: &[char]) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    let spans = [
        (Detector::Email, emails(c)),
        (Detector::Phone, phones(c)),
        (Detector::CnResidentId, cn_ids(c)),
        (Detector::PaymentCard, cards(c)),
        (Detector::IpAddress, ips(c)),
        (Detector::MacAddress, macs(c)),
        (Detector::UserHomePath, home_paths(c)),
        (Detector::PersonNameEn, names_en(c)),
        (Detector::PersonNameZh, names_zh(c)),
        (Detector::OrgMarker, orgs(c)),
        (Detector::ContractMarker, contract_markers(c)),
    ];
    for (detector, list) in spans {
        out.extend(list.into_iter().map(|(start, len)| (detector, start, len)));
    }
    for url in urls(c) {
        if url.userinfo {
            out.push((Detector::UrlUserinfo, url.start, url.len));
        }
        if url.key_value {
            out.push((Detector::UrlQuery, url.start, url.len));
        }
    }
    out
}

fn combined(quasi: &[QuasiHit]) -> Vec<Hit> {
    let mut firsts: Vec<QuasiHit> = Vec::new();
    for hit in quasi {
        if !firsts.iter().any(|f| f.0 == hit.0) {
            firsts.push(*hit);
        }
    }
    if firsts.len() < COMBINED_FLOOR {
        return Vec::new();
    }
    firsts
        .into_iter()
        .map(|(_, surface, char_offset, len)| Hit {
            detector: Detector::CombinedIdentifiability,
            surface,
            char_offset,
            len,
        })
        .collect()
}

// ponytail: heuristics only (U3); the model check lands after E-M20-1 and its home is the A5-bound model leg.

fn is_word(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn is_han(ch: char) -> bool {
    ('\u{4e00}'..='\u{9fff}').contains(&ch)
}

fn prev_is_alnum(c: &[char], i: usize) -> bool {
    i > 0 && c[i - 1].is_ascii_alphanumeric()
}

fn starts_with(c: &[char], i: usize, pat: &str) -> bool {
    pat.chars()
        .enumerate()
        .all(|(k, p)| c.get(i + k) == Some(&p))
}

fn digits_at(c: &[char], i: usize, n: usize) -> bool {
    i + n <= c.len() && c[i..i + n].iter().all(char::is_ascii_digit)
}

fn num(c: &[char]) -> u32 {
    c.iter()
        .filter_map(|x| x.to_digit(10))
        .fold(0, |acc, d| acc * 10 + d)
}

fn slice_text(c: &[char], span: Span) -> String {
    c[span.0..span.0 + span.1].iter().collect()
}

/// Maximal runs of ASCII letters, digits and underscore.
fn words(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if is_word(c[i]) {
            let start = i;
            while i < c.len() && is_word(c[i]) {
                i += 1;
            }
            out.push((start, i - start));
        } else {
            i += 1;
        }
    }
    out
}

fn has_key_value(part: &[char]) -> bool {
    part.windows(2)
        .any(|w| w[1] == '=' && (w[0].is_alphanumeric() || w[0] == '_'))
}

fn entries(raw: &'static str) -> Vec<&'static str> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn given_names() -> &'static [&'static str] {
    static CELL: OnceLock<Vec<&'static str>> = OnceLock::new();
    CELL.get_or_init(|| entries(include_str!("deid_names_en.txt")))
        .as_slice()
}

fn place_names() -> &'static [&'static str] {
    static CELL: OnceLock<Vec<&'static str>> = OnceLock::new();
    CELL.get_or_init(|| entries(include_str!("deid_places.txt")))
        .as_slice()
}

fn role_phrases() -> &'static [&'static str] {
    static CELL: OnceLock<Vec<&'static str>> = OnceLock::new();
    CELL.get_or_init(|| entries(include_str!("deid_roles.txt")))
        .as_slice()
}

fn surnames() -> &'static [char] {
    static CELL: OnceLock<Vec<char>> = OnceLock::new();
    CELL.get_or_init(|| {
        entries(include_str!("deid_surnames_zh.txt"))
            .into_iter()
            .flat_map(str::split_whitespace)
            .filter_map(|token| token.chars().next())
            .collect()
    })
    .as_slice()
}

// ---- email -------------------------------------------------------------------------------------------------------

fn is_local(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-')
}

fn emails(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] == '@'
            && let Some(span) = email_at(c, i)
        {
            out.push(span);
            i = span.0 + span.1;
        } else {
            i += 1;
        }
    }
    out
}

fn email_at(c: &[char], at: usize) -> Option<Span> {
    let mut start = at;
    while start > 0 && is_local(c[start - 1]) {
        start -= 1;
    }
    if start == at {
        return None;
    }
    let mut end = at + 1;
    while end < c.len() && (c[end].is_ascii_alphanumeric() || matches!(c[end], '.' | '-')) {
        end += 1;
    }
    while end > at + 1 && matches!(c[end - 1], '.' | '-') {
        end -= 1;
    }
    let domain = &c[at + 1..end];
    let dot = domain.iter().rposition(|x| *x == '.')?;
    let tld = &domain[dot + 1..];
    (dot > 0 && tld.len() >= 2 && tld.iter().all(char::is_ascii_alphabetic))
        .then_some((start, end - start))
}

// ---- phone -------------------------------------------------------------------------------------------------------

fn phones(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let found = if c[i] == '+' {
            intl_phone(c, i)
        } else if c[i].is_ascii_digit() {
            cn_mobile(c, i)
        } else {
            None
        };
        if let Some(span) = found {
            out.push(span);
            i = span.0 + span.1;
        } else {
            i += 1;
        }
    }
    out
}

fn is_phone_sep(ch: char) -> bool {
    matches!(ch, ' ' | '-' | '.' | '(' | ')')
}

/// `+` followed by 8-15 digits, with up to two separator chars between digits.
fn intl_phone(c: &[char], plus: usize) -> Option<Span> {
    if prev_is_alnum(c, plus) || !c.get(plus + 1).is_some_and(char::is_ascii_digit) {
        return None;
    }
    let mut j = plus + 1;
    let mut digits = 0;
    let mut end = plus + 1;
    while j < c.len() {
        if c[j].is_ascii_digit() {
            digits += 1;
            j += 1;
            end = j;
            continue;
        }
        let mut k = j;
        while k < c.len() && k < j + 2 && is_phone_sep(c[k]) {
            k += 1;
        }
        if k > j && c.get(k).is_some_and(char::is_ascii_digit) {
            j = k;
        } else {
            break;
        }
    }
    (8..=15).contains(&digits).then_some((plus, end - plus))
}

/// CN mobile: 1[3-9] plus nine digits, compact or grouped 3-4-4 by one space or dash.
fn cn_mobile(c: &[char], s: usize) -> Option<Span> {
    if (s > 0 && c[s - 1].is_ascii_digit())
        || c[s] != '1'
        || !c.get(s + 1).is_some_and(|x| ('3'..='9').contains(x))
    {
        return None;
    }
    if digits_at(c, s, 11) && !c.get(s + 11).is_some_and(char::is_ascii_digit) {
        return Some((s, 11));
    }
    let sep = *c.get(s + 3)?;
    let grouped = matches!(sep, ' ' | '-')
        && digits_at(c, s, 3)
        && c.get(s + 8) == Some(&sep)
        && digits_at(c, s + 4, 4)
        && digits_at(c, s + 9, 4)
        && !c.get(s + 13).is_some_and(char::is_ascii_digit);
    grouped.then_some((s, 13))
}

// ---- CN resident ID ----------------------------------------------------------------------------------------------

const ID_WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const ID_CHECK: [char; 11] = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];

fn cn_ids(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 18 <= c.len() {
        if cn_id_at(c, i) {
            out.push((i, 18));
            i += 18;
        } else {
            i += 1;
        }
    }
    out
}

fn cn_id_at(c: &[char], s: usize) -> bool {
    if prev_is_alnum(c, s) || c.get(s + 18).is_some_and(char::is_ascii_alphanumeric) {
        return false;
    }
    let id = &c[s..s + 18];
    if id[0] == '0' || !id[..17].iter().all(char::is_ascii_digit) {
        return false;
    }
    if !valid_ymd(num(&id[6..10]), num(&id[10..12]), num(&id[12..14])) {
        return false;
    }
    let sum: u32 = id[..17]
        .iter()
        .zip(ID_WEIGHTS)
        .map(|(d, w)| d.to_digit(10).unwrap_or(0) * w)
        .sum();
    id[17].to_ascii_uppercase() == ID_CHECK[(sum % 11) as usize]
}

fn valid_ymd(y: u32, m: u32, d: u32) -> bool {
    (1900..=2099).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d)
}

// ---- payment card ------------------------------------------------------------------------------------------------

fn cards(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let digit_before = i > 0 && c[i - 1].is_ascii_digit();
        if c[i].is_ascii_digit()
            && !digit_before
            && let Some(span) = card_at(c, i)
        {
            out.push(span);
            i = span.0 + span.1;
        } else {
            i += 1;
        }
    }
    out
}

fn card_at(c: &[char], s: usize) -> Option<Span> {
    let mut digits: Vec<u32> = Vec::new();
    let mut j = s;
    let mut end = s;
    while j < c.len() {
        if let Some(d) = c[j].to_digit(10) {
            digits.push(d);
            j += 1;
            end = j;
        } else if matches!(c[j], ' ' | '-') && c.get(j + 1).is_some_and(char::is_ascii_digit) {
            j += 1;
        } else {
            break;
        }
    }
    ((13..=19).contains(&digits.len()) && luhn(&digits)).then_some((s, end - s))
}

fn luhn(digits: &[u32]) -> bool {
    let mut sum: u32 = 0;
    let mut double = false;
    for d in digits.iter().rev() {
        let v = if double { *d * 2 } else { *d };
        sum += v / 10 + v % 10;
        double = !double;
    }
    sum.is_multiple_of(10)
}

// ---- IP and MAC --------------------------------------------------------------------------------------------------

fn ips(c: &[char]) -> Vec<Span> {
    let mut out = ipv4s(c);
    out.extend(ipv6s(c));
    out
}

fn ipv4s(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if c[i].is_ascii_digit()
            && let Some(span) = ipv4_at(c, i)
        {
            out.push(span);
            i = span.0 + span.1;
        } else {
            i += 1;
        }
    }
    out
}

fn ipv4_at(c: &[char], s: usize) -> Option<Span> {
    if s > 0 && (c[s - 1].is_ascii_alphanumeric() || c[s - 1] == '.') {
        return None;
    }
    let mut octets = [0u32; 4];
    let mut j = s;
    for (k, slot) in octets.iter_mut().enumerate() {
        let n = c[j..]
            .iter()
            .take(3)
            .take_while(|x| x.is_ascii_digit())
            .count();
        if n == 0 {
            return None;
        }
        *slot = num(&c[j..j + n]);
        j += n;
        if k < 3 {
            if c.get(j) != Some(&'.') {
                return None;
            }
            j += 1;
        }
    }
    let glued = c.get(j).is_some_and(char::is_ascii_digit)
        || (c.get(j) == Some(&'.') && c.get(j + 1).is_some_and(char::is_ascii_digit));
    if glued || octets.iter().any(|o| *o > 255) || ipv4_reserved(octets) {
        return None;
    }
    Some((s, j - s))
}

/// Documentation (RFC 5737), loopback, private, unspecified and broadcast IPv4 ranges do not identify anyone.
fn ipv4_reserved(o: [u32; 4]) -> bool {
    matches!(
        o,
        [0 | 10 | 127, ..]
            | [172, 16..=31, ..]
            | [192, 168, ..]
            | [192, 0, 2, _]
            | [198, 51, 100, _]
            | [203, 0, 113, _]
            | [255, 255, 255, 255]
    )
}

fn ipv6s(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let hexish = c[i].is_ascii_hexdigit() || c[i] == ':';
        let lone_colon = c[i] == ':' && c.get(i + 1) != Some(&':');
        if !hexish || lone_colon {
            i += 1;
            continue;
        }
        let mut e = i;
        while e < c.len() && (c[e].is_ascii_hexdigit() || c[e] == ':') {
            e += 1;
        }
        while e > i + 1 && c[e - 1] == ':' && c[e - 2] != ':' {
            e -= 1;
        }
        let token: String = c[i..e].iter().collect();
        let clean = !prev_is_alnum(c, i) && !c.get(e).is_some_and(char::is_ascii_alphanumeric);
        if clean
            && token.chars().any(|x| x.is_ascii_digit())
            && parse_ipv6(&token).is_some_and(|g| ipv6_public(&g))
        {
            out.push((i, e - i));
        }
        i = e.max(i + 1);
    }
    out
}

fn parse_ipv6(s: &str) -> Option<[u16; 8]> {
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let groups = |part: &str| -> Option<Vec<u16>> {
        if part.is_empty() {
            return Some(Vec::new());
        }
        part.split(':')
            .map(|g| {
                if g.len() <= 4 {
                    u16::from_str_radix(g, 16).ok()
                } else {
                    None
                }
            })
            .collect()
    };
    let head = groups(head)?;
    let mut out = [0u16; 8];
    match tail {
        None => {
            if head.len() != 8 {
                return None;
            }
            out.copy_from_slice(&head);
        }
        Some(t) => {
            let tail = groups(t)?;
            if head.len() + tail.len() > 7 {
                return None;
            }
            out[..head.len()].copy_from_slice(&head);
            out[8 - tail.len()..].copy_from_slice(&tail);
        }
    }
    Some(out)
}

/// Not unspecified, loopback, documentation (2001:db8::/32, 3fff::/20) or unique-local (fc00::/7).
fn ipv6_public(g: &[u16; 8]) -> bool {
    let unspecified_or_loopback = g[..7].iter().all(|x| *x == 0) && g[7] <= 1;
    let documentation = (g[0] == 0x2001 && g[1] == 0x0db8) || (g[0] == 0x3fff && g[1] <= 0x0fff);
    let unique_local = (g[0] & 0xfe00) == 0xfc00;
    !(unspecified_or_loopback || documentation || unique_local)
}

fn macs(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 17 <= c.len() {
        if mac_at(c, i) {
            out.push((i, 17));
            i += 17;
        } else {
            i += 1;
        }
    }
    out
}

fn mac_at(c: &[char], s: usize) -> bool {
    let sep = c[s + 2];
    let edge = |x: &char| x.is_ascii_alphanumeric() || *x == ':' || *x == '-';
    let before = s > 0 && edge(&c[s - 1]);
    let after = c.get(s + 17).is_some_and(edge);
    (sep == ':' || sep == '-')
        && !before
        && !after
        && (0..6).all(|k| {
            let p = s + k * 3;
            c[p].is_ascii_hexdigit() && c[p + 1].is_ascii_hexdigit() && (k == 5 || c[p + 2] == sep)
        })
}

// ---- paths -------------------------------------------------------------------------------------------------------

/// Generic placeholder user names that identify nobody.
const PLACEHOLDER_USERS: &[&str] = &["user", "username", "you", "yourname", "example", "name"];

fn home_paths(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    for i in 0..c.len() {
        let glued =
            i > 0 && (c[i - 1].is_ascii_alphanumeric() || matches!(c[i - 1], '.' | '-' | '_'));
        if glued {
            continue;
        }
        if let Some(end) = home_end(c, i) {
            out.push((i, end - i));
        }
    }
    out
}

fn home_end(c: &[char], i: usize) -> Option<usize> {
    if starts_with(c, i, "/Users/") {
        return name_end(c, i + 7);
    }
    if starts_with(c, i, "/home/") {
        return name_end(c, i + 6);
    }
    if c[i] == '~' {
        let end = name_end(c, i + 1)?;
        return (c.get(end) == Some(&'/') && c[i + 1].is_alphabetic()).then_some(end);
    }
    win_home(c, i)
}

/// End of a user name starting at `j`, or None when it is empty or a placeholder. Letters and digits of any script count.
fn name_end(c: &[char], j: usize) -> Option<usize> {
    let mut end = j;
    while end < c.len() && (c[end].is_alphanumeric() || matches!(c[end], '.' | '_' | '-')) {
        end += 1;
    }
    let name: String = c[j..end].iter().collect::<String>().to_lowercase();
    let first_ok = c.get(j).is_some_and(|x| x.is_alphanumeric());
    (first_ok && !PLACEHOLDER_USERS.contains(&name.as_str())).then_some(end)
}

fn skip_seps(c: &[char], j: usize) -> Option<usize> {
    let n = c[j.min(c.len())..]
        .iter()
        .take(2)
        .take_while(|x| matches!(**x, '\\' | '/'))
        .count();
    (n > 0).then_some(j + n)
}

fn win_home(c: &[char], i: usize) -> Option<usize> {
    if !c[i].is_ascii_alphabetic() || c.get(i + 1) != Some(&':') {
        return None;
    }
    let j = skip_seps(c, i + 2)?;
    // Windows paths are case-insensitive: `c:\users\` names the same directory.
    if !c[j..]
        .iter()
        .take(5)
        .map(char::to_ascii_lowercase)
        .eq("users".chars())
    {
        return None;
    }
    name_end(c, skip_seps(c, j + 5)?)
}

// ---- URLs --------------------------------------------------------------------------------------------------------

struct UrlParts {
    start: usize,
    len: usize,
    userinfo: bool,
    key_value: bool,
}

fn url_char(ch: char) -> bool {
    ch.is_ascii_graphic()
        && !matches!(
            ch,
            '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '`' | '\\'
        )
}

fn urls(c: &[char]) -> Vec<UrlParts> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if starts_with(c, i, "://")
            && let Some(url) = url_at(c, i)
        {
            i = url.start + url.len;
            out.push(url);
        } else {
            i += 1;
        }
    }
    out
}

fn url_at(c: &[char], sep: usize) -> Option<UrlParts> {
    let mut start = sep;
    while start > 0
        && (c[start - 1].is_ascii_alphabetic() || matches!(c[start - 1], '+' | '-' | '.'))
    {
        start -= 1;
    }
    if start == sep {
        return None;
    }
    let mut end = sep + 3;
    while end < c.len() && url_char(c[end]) {
        end += 1;
    }
    let body = &c[sep + 3..end];
    let auth_end = body
        .iter()
        .position(|x| matches!(*x, '/' | '?' | '#'))
        .unwrap_or(body.len());
    let tail = &body[auth_end..];
    let key_value = tail
        .iter()
        .position(|x| matches!(*x, '?' | '#'))
        .is_some_and(|p| has_key_value(&tail[p + 1..]));
    Some(UrlParts {
        start,
        len: end - start,
        userinfo: body[..auth_end].contains(&'@'),
        key_value,
    })
}

// ---- names, organisations, contract markers ----------------------------------------------------------------------

const HONORIFICS: &[&str] = &["Mr", "Mrs", "Ms", "Dr", "Prof"];

fn is_proper(word: &str) -> bool {
    word.len() >= 2 && word.chars().next().is_some_and(|f| f.is_ascii_uppercase())
}

fn is_capitalised(word: &str) -> bool {
    let mut it = word.chars();
    it.next().is_some_and(|f| f.is_ascii_uppercase())
        && word.len() >= 3
        && it.all(|x| x.is_ascii_lowercase())
}

fn names_en(c: &[char]) -> Vec<Span> {
    let ws = words(c);
    let mut out = Vec::new();
    for (k, w) in ws.iter().enumerate() {
        let word = slice_text(c, *w);
        if given_names().contains(&word.as_str()) {
            out.push(*w);
        } else if HONORIFICS.contains(&word.as_str())
            && let Some(next) = ws.get(k + 1)
            && is_capitalised(&slice_text(c, *next))
            && gap_between(c, *w, *next, &['.', ' '], 3)
        {
            out.push((w.0, next.0 + next.1 - w.0));
        }
    }
    out
}

/// True when 1..=`max` chars, all among `allowed`, separate word `a` from the later word `b`.
fn gap_between(c: &[char], a: Span, b: Span, allowed: &[char], max: usize) -> bool {
    let from = a.0 + a.1;
    from < b.0 && b.0 - from <= max && c[from..b.0].iter().all(|x| allowed.contains(x))
}

const ZH_NAME_MARKERS: &[&str] = &[
    "我叫",
    "联系人",
    "负责人",
    "姓名",
    "经办人",
    "申请人",
    "对接人",
    "我的名字是",
    "Mr",
    "Mrs",
    "Ms",
    "Dr",
    "Prof",
];

/// Courtesy titles that follow a Han name (`王芳博士`, `王先生`).
const ZH_TITLES: &[&str] = &["先生", "女士", "小姐", "博士", "教授"];

fn names_zh(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    for i in 0..c.len() {
        for marker in ZH_NAME_MARKERS {
            // ASCII honorifics start a word; a Han marker may sit inside a sentence.
            let bounded = !(marker.is_ascii() && prev_is_alnum(c, i));
            if bounded
                && starts_with(c, i, marker)
                && let Some(span) = zh_name_after(c, i + marker.chars().count())
            {
                out.push(span);
            }
        }
        out.extend(zh_titled_name(c, i));
    }
    out
}

/// A dictionary surname, up to two more Han characters, then a courtesy title.
fn zh_titled_name(c: &[char], i: usize) -> Option<Span> {
    if !surnames().contains(&c[i]) {
        return None;
    }
    let extra = c[i + 1..]
        .iter()
        .take(2)
        .take_while(|x| is_han(**x))
        .count();
    (0..=extra)
        .rev()
        .find(|k| ZH_TITLES.iter().any(|t| starts_with(c, i + 1 + k, t)))
        .map(|k| (i, 1 + k))
}

fn zh_name_after(c: &[char], start: usize) -> Option<Span> {
    let mut j = start;
    while j < start + 3
        && c.get(j)
            .is_some_and(|x| matches!(*x, ':' | '：' | ' ' | '.' | '是' | '为'))
    {
        j += 1;
    }
    let first = *c.get(j)?;
    if !surnames().contains(&first) {
        return None;
    }
    let extra = c[j + 1..]
        .iter()
        .take(2)
        .take_while(|x| is_han(**x))
        .count();
    (extra >= 1).then_some((j, 1 + extra))
}

const ORG_SUFFIX_EN: &[&str] = &["Inc", "Ltd", "LLC", "GmbH", "Corp", "PLC", "Pty"];
const ORG_SUFFIX_ZH: &[&str] = &["有限责任公司", "有限公司"];

fn orgs(c: &[char]) -> Vec<Span> {
    let mut out = orgs_en(c);
    out.extend(orgs_zh(c));
    out
}

fn orgs_en(c: &[char]) -> Vec<Span> {
    let ws = words(c);
    let mut out = Vec::new();
    for pair in ws.windows(2) {
        let (prev, suffix) = (pair[0], pair[1]);
        let name = slice_text(c, prev);
        let tail = slice_text(c, suffix);
        if ORG_SUFFIX_EN.contains(&tail.as_str())
            && is_proper(&name)
            && !ORG_SUFFIX_EN.contains(&name.as_str())
            && gap_between(c, prev, suffix, &[' ', ','], 2)
        {
            let dot = usize::from(c.get(suffix.0 + suffix.1) == Some(&'.'));
            out.push((prev.0, suffix.0 + suffix.1 + dot - prev.0));
        }
    }
    out
}

fn orgs_zh(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let suffix = ORG_SUFFIX_ZH.iter().find(|s| starts_with(c, i, s));
        if let Some(s) = suffix {
            let n = s.chars().count();
            let back = (1..=8).take_while(|k| i >= *k && is_han(c[i - *k])).count();
            if back >= 2 {
                out.push((i - back, back + n));
            }
            i += n;
        } else {
            i += 1;
        }
    }
    out
}

const CONTRACT_MARKERS: &[&str] = &[
    "confidential",
    "do not distribute",
    "trade secret",
    "contract number",
    "保密",
    "合同编号",
    "内部资料",
    "商业秘密",
];

fn contract_markers(c: &[char]) -> Vec<Span> {
    let lower: Vec<char> = c.iter().map(char::to_ascii_lowercase).collect();
    let mut out = Vec::new();
    for i in 0..lower.len() {
        for marker in CONTRACT_MARKERS {
            if starts_with(&lower, i, marker) {
                out.push((i, marker.chars().count()));
            }
        }
    }
    for w in words(c) {
        if slice_text(c, w) == "NDA" {
            out.push(w);
        }
    }
    out
}

// ---- combined identifiability: quasi-identifier classes ----------------------------------------------------------

/// The six quasi-identifier classes of the combined floor (D6').
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quasi {
    FullDate,
    Place,
    Org,
    Role,
    Age,
    Gender,
}

const GENDER_WORDS: &[&str] = &[
    "male",
    "female",
    "woman",
    "women",
    "boy",
    "girl",
    "he",
    "she",
    "husband",
    "wife",
    "gentleman",
    "lady",
    "男性",
    "女性",
    "先生",
    "女士",
    "男生",
    "女生",
    "小姐",
    "性别:",
    "性别：",
];

fn quasi_hits(c: &[char]) -> Vec<(Quasi, usize, usize)> {
    let classes = [
        (Quasi::FullDate, full_dates(c)),
        (Quasi::Place, places(c)),
        (Quasi::Org, orgs(c)),
        (Quasi::Role, find_all(c, role_phrases(), true)),
        (Quasi::Age, ages(c)),
        (Quasi::Gender, gender_spans(c)),
    ];
    let mut out = Vec::new();
    for (class, spans) in classes {
        out.extend(spans.into_iter().map(|(start, len)| (class, start, len)));
    }
    out
}

fn gender_spans(c: &[char]) -> Vec<Span> {
    let mut out = find_all(c, GENDER_WORDS, true);
    out.extend(gender_fields(c));
    out
}

/// A form field such as `Gender: F`: the label, a colon, optional spaces and a one-letter value.
fn gender_fields(c: &[char]) -> Vec<Span> {
    let low: Vec<char> = c.iter().map(char::to_ascii_lowercase).collect();
    let mut out = Vec::new();
    for i in 0..low.len() {
        if !starts_with(&low, i, "gender:") || label_glued(&low, i) {
            continue;
        }
        let mut j = i + 7;
        while low.get(j) == Some(&' ') {
            j += 1;
        }
        let value = low.get(j).is_some_and(|x| matches!(*x, 'm' | 'f'));
        if value && !low.get(j + 1).is_some_and(char::is_ascii_alphanumeric) {
            out.push((i, j + 1 - i));
        }
    }
    out
}

/// True when the label at `i` is the tail of a longer identifier (`max-age`, `user_gender`).
fn label_glued(l: &[char], i: usize) -> bool {
    i > 0 && (l[i - 1].is_ascii_alphanumeric() || matches!(l[i - 1], '-' | '_'))
}

/// Occurrences of `phrases`; ASCII phrases must be whole words, `fold` compares ASCII case-insensitively (phrases lowercase).
fn find_all(c: &[char], phrases: &[&str], fold: bool) -> Vec<Span> {
    let hay: Vec<char> = if fold {
        c.iter().map(char::to_ascii_lowercase).collect()
    } else {
        c.to_vec()
    };
    let mut out = Vec::new();
    for i in 0..hay.len() {
        for phrase in phrases {
            let n = phrase.chars().count();
            let bounded = !phrase.is_ascii()
                || (!prev_is_alnum(&hay, i)
                    && !hay.get(i + n).is_some_and(char::is_ascii_alphanumeric));
            if bounded && starts_with(&hay, i, phrase) {
                out.push((i, n));
            }
        }
    }
    out
}

fn places(c: &[char]) -> Vec<Span> {
    let mut out = find_all(c, place_names(), false);
    out.extend(streets_en(c));
    out.extend(streets_zh(c));
    out
}

const STREET_EN: &[&str] = &["Street", "Road", "Avenue", "Boulevard", "Lane", "Blvd"];

fn streets_en(c: &[char]) -> Vec<Span> {
    let ws = words(c);
    let mut out = Vec::new();
    for pair in ws.windows(2) {
        let (prev, street) = (pair[0], pair[1]);
        if STREET_EN.contains(&slice_text(c, street).as_str())
            && is_proper(&slice_text(c, prev))
            && gap_between(c, prev, street, &[' '], 1)
        {
            out.push((prev.0, street.0 + street.1 - prev.0));
        }
    }
    out
}

fn streets_zh(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    for (i, ch) in c.iter().enumerate() {
        if matches!(*ch, '路' | '街' | '巷')
            && let Some(span) = zh_street_at(c, i)
        {
            out.push(span);
        }
    }
    out
}

/// Han chars, then 路/街/巷, then digits, then 号.
fn zh_street_at(c: &[char], i: usize) -> Option<Span> {
    let back = (1..=6).take_while(|k| i >= *k && is_han(c[i - *k])).count();
    let digits = c[i + 1..]
        .iter()
        .take(5)
        .take_while(|x| x.is_ascii_digit())
        .count();
    (back >= 1 && digits >= 1 && c.get(i + 1 + digits) == Some(&'号'))
        .then_some((i - back, back + 1 + digits + 1))
}

const MONTHS: &[&str] = &[
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Sept",
    "Oct",
    "Nov",
    "Dec",
];

fn full_dates(c: &[char]) -> Vec<Span> {
    let mut raw = numeric_dates(c);
    raw.extend(zh_dates(c));
    raw.extend(en_dates(c));
    raw.into_iter()
        .filter(|(start, len)| !release_context(c, *start, *start + *len))
        .collect()
}

fn digit_run(c: &[char], from: usize, max: usize) -> Option<(u32, usize)> {
    let n = c
        .get(from..)?
        .iter()
        .take(max)
        .take_while(|x| x.is_ascii_digit())
        .count();
    if n == 0 {
        None
    } else {
        Some((num(&c[from..from + n]), from + n))
    }
}

fn numeric_dates(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 8 <= c.len() {
        if let Some(len) = iso_date_at(c, i) {
            out.push((i, len));
            i += len;
        } else {
            i += 1;
        }
    }
    out
}

/// `YYYY-MM-DD`, `YYYY/MM/DD` or `YYYY.MM.DD` with one repeated separator.
fn iso_date_at(c: &[char], s: usize) -> Option<usize> {
    if (s > 0 && c[s - 1].is_ascii_digit()) || !digits_at(c, s, 4) {
        return None;
    }
    let sep = *c.get(s + 4)?;
    if !matches!(sep, '-' | '/' | '.') {
        return None;
    }
    let (month, j) = digit_run(c, s + 5, 2)?;
    if c.get(j) != Some(&sep) {
        return None;
    }
    let (day, k) = digit_run(c, j + 1, 2)?;
    if c.get(k).is_some_and(char::is_ascii_digit) {
        return None;
    }
    valid_ymd(num(&c[s..s + 4]), month, day).then_some(k - s)
}

fn zh_dates(c: &[char]) -> Vec<Span> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 9 <= c.len() {
        if let Some(len) = zh_date_at(c, i) {
            out.push((i, len));
            i += len;
        } else {
            i += 1;
        }
    }
    out
}

/// `YYYY年M月D日` (or 号).
fn zh_date_at(c: &[char], s: usize) -> Option<usize> {
    if (s > 0 && c[s - 1].is_ascii_digit()) || !digits_at(c, s, 4) || c.get(s + 4) != Some(&'年') {
        return None;
    }
    let (month, j) = digit_run(c, s + 5, 2)?;
    if c.get(j) != Some(&'月') {
        return None;
    }
    let (day, k) = digit_run(c, j + 1, 2)?;
    (matches!(c.get(k).copied(), Some('日' | '号')) && valid_ymd(num(&c[s..s + 4]), month, day))
        .then_some(k + 1 - s)
}

fn is_year(word: &str) -> bool {
    word.len() == 4
        && word.chars().all(|x| x.is_ascii_digit())
        && (1900..=2099).contains(&word.parse::<u32>().unwrap_or(0))
}

fn is_day(word: &str) -> bool {
    let digits: String = word.chars().take_while(char::is_ascii_digit).collect();
    let rest = &word[digits.len()..];
    (1..=2).contains(&digits.len())
        && matches!(rest, "" | "st" | "nd" | "rd" | "th")
        && (1..=31).contains(&digits.parse::<u32>().unwrap_or(0))
}

fn day_year(c: &[char], day: Span, year: Span) -> bool {
    is_day(&slice_text(c, day)) && is_year(&slice_text(c, year))
}

/// `Month D[,] YYYY` and `D Month YYYY`.
fn en_dates(c: &[char]) -> Vec<Span> {
    let ws = words(c);
    let mut out = Vec::new();
    for (k, w) in ws.iter().enumerate() {
        if !MONTHS.contains(&slice_text(c, *w).as_str()) {
            continue;
        }
        if let (Some(&day), Some(&year)) = (ws.get(k + 1), ws.get(k + 2))
            && day_year(c, day, year)
            && gap_between(c, *w, day, &[' ', ',', '.'], 2)
            && gap_between(c, day, year, &[' ', ',', '.'], 2)
        {
            out.push((w.0, year.0 + year.1 - w.0));
        } else if k > 0
            && let (Some(&day), Some(&year)) = (ws.get(k - 1), ws.get(k + 1))
            && day_year(c, day, year)
            && gap_between(c, day, *w, &[' ', ',', '.'], 2)
            && gap_between(c, *w, year, &[' ', ',', '.'], 2)
        {
            out.push((day.0, year.0 + year.1 - day.0));
        }
    }
    out
}

const RELEASE_WORDS: &[&str] = &["releas", "changelog", "version"];

/// A date inside a release or changelog line is a software date, not a person's (D6' exclusion).
fn release_context(c: &[char], start: usize, end: usize) -> bool {
    let line_start = c[..start]
        .iter()
        .rposition(|x| *x == '\n')
        .map_or(0, |p| p + 1);
    let line_end = c[end..]
        .iter()
        .position(|x| *x == '\n')
        .map_or(c.len(), |p| end + p);
    let lo = line_start.max(start.saturating_sub(RELEASE_WINDOW));
    let hi = line_end.min(end + RELEASE_WINDOW);
    near_release(&c[lo..start]) || near_release(&c[end..hi])
}

fn near_release(window: &[char]) -> bool {
    let low: Vec<char> = window.iter().map(char::to_ascii_lowercase).collect();
    let flat: String = low.iter().collect();
    RELEASE_WORDS.iter().any(|k| flat.contains(*k))
        || (0..low.len()).any(|i| v_digit(&low, i) || semver_at(&low, i))
}

fn v_digit(l: &[char], i: usize) -> bool {
    l[i] == 'v' && l.get(i + 1).is_some_and(char::is_ascii_digit) && !prev_is_alnum(l, i)
}

fn semver_at(l: &[char], i: usize) -> bool {
    l[i].is_ascii_digit()
        && l.get(i + 1) == Some(&'.')
        && l.get(i + 2).is_some_and(char::is_ascii_digit)
        && l.get(i + 3) == Some(&'.')
        && l.get(i + 4).is_some_and(char::is_ascii_digit)
}

const AGE_SUFFIX: &[&str] = &["-year-old", " year old", " years old", "-years-old", "岁"];

fn ages(c: &[char]) -> Vec<Span> {
    let lower: Vec<char> = c.iter().map(char::to_ascii_lowercase).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lower.len() {
        let digit_before = i > 0 && lower[i - 1].is_ascii_digit();
        if lower[i].is_ascii_digit()
            && !digit_before
            && let Some(len) = age_at(&lower, i)
        {
            out.push((i, len));
            i += len;
        } else {
            i += 1;
        }
    }
    out
}

/// `age: 34` or `年龄：34`: the label, one colon and optional spaces precede the number at `s`.
fn labelled_age(l: &[char], s: usize) -> bool {
    let mut p = s;
    while p > 0 && l[p - 1] == ' ' {
        p -= 1;
    }
    if p == 0 || !matches!(l[p - 1], ':' | '：') {
        return false;
    }
    let colon = p - 1;
    (colon >= 3 && starts_with(l, colon - 3, "age") && !label_glued(l, colon - 3))
        || (colon >= 2 && starts_with(l, colon - 2, "年龄"))
}

/// `34-year-old`, `34 years old`, `34岁`, `aged 34` or a labelled `age: 34`.
fn age_at(l: &[char], s: usize) -> Option<usize> {
    let n = l[s..]
        .iter()
        .take(3)
        .take_while(|x| x.is_ascii_digit())
        .count();
    if !(1..=120).contains(&num(&l[s..s + n])) || l.get(s + n).is_some_and(char::is_ascii_digit) {
        return None;
    }
    let suffix = AGE_SUFFIX.iter().find(|p| starts_with(l, s + n, p));
    let aged = (s >= 5 && starts_with(l, s - 5, "aged ")) || labelled_age(l, s);
    match (suffix, aged) {
        (Some(p), _) => Some(n + p.chars().count()),
        (None, true) => Some(n),
        (None, false) => None,
    }
}
