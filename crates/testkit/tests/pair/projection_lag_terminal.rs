//! `testkit::tests::pair::projection_lag_terminal` — terminal wire assertion for the §52.2 projection-lag pair.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [gateway::tests::mcp_gateway]
//! Invariants: [the paired fixture exercises the Gateway endpoint before asserting the wire result]
//! Spec: Baseline §52.2; ADR-0134

pub(super) fn assert_terminal_projection_lag(
    is_error: bool,
    code: Option<&str>,
    has_success_fields: bool,
    response: &str,
) {
    assert!(is_error, "strict recall returned a result: {response}");
    assert_eq!(code, Some("PROJECTION_LAG"), "{response}");
    assert!(
        !has_success_fields,
        "terminal recall carried result or degradations: {response}"
    );
}
