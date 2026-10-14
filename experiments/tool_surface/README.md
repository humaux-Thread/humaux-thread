# Tool-surface experiment (X2 tool count / grouping, X4 descriptions)

Question: how many MCP tools, grouped how, lets agents pick the right Humaux Thread action with valid arguments —
on MiniMax (default model) and Claude (control)? Design: `mcp_tool_surface_design_v1.md` + GPT batch 22 review.

- `catalog.py` — 72 canonical actions (B22's 18-tool surface: 15 OSS + 3 cloud).
- `variants.py` — arms A8 (today's object grouping), B11, C14 (design v1), D18 (B22), E30 (by effect), P (one tool per
  action, 72), flat profile.
- `scenarios.py` — pilot suite: every job family, B22's confusion pairs, no-call cases, EN/ZH.
- `stub_server.py` — stdio MCP server serving one arm, logging calls; no real backend.
- `run.py` — headless Claude Code episodes, graded on the first Humaux call.
- CI: `.github/workflows/exp-tool-surface.yml`, runs on pushes to `exp/tool-surface` only.
Results are artifacts of that workflow; nothing here touches the product code or any real data.
