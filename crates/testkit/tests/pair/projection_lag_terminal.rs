//! `testkit::tests::pair::projection_lag_terminal` — §52.2 registered terminal wire assertion.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [gateway::tests::mcp_gateway]
//! Invariants: [terminal projection lag carries no successful items or degradations]
//! Spec: Baseline §52.2; ADR-0134

macro_rules! assert_projection_lag_terminal {
    ($status:expr, $wire:expr) => {{
        let wire = $wire;
        let result = &wire["result"];
        let content = &result["structuredContent"];
        assert_eq!($status, 200, "MCP tool error: {wire}");
        assert!(wire.get("error").is_none(), "{wire}");
        assert_eq!(result["isError"], true, "strict projection lag: {wire}");
        assert_eq!(content["code"], "PROJECTION_LAG", "{wire}");
        assert!(
            content.as_object().is_some_and(|fields| fields.len() == 1),
            "{wire}"
        );
        assert!(result.get("degradations").is_none(), "{wire}");
    }};
}

pub(super) use assert_projection_lag_terminal;
