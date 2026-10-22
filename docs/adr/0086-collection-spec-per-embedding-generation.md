# ADR-0086 — CollectionSpec: one typed description of a Qdrant collection per embedding generation

- Status: Accepted (2026-10-22). Card M10-1 (wave B, module M10). Design note: `module_design_M10.md` §2, §6 D1/D2,
  §9; cross-module contract C7 of the wave B overview.
- Relates to: Baseline §17, §17.1, §17.3, §17.5, §17.7, §50, §78.1; ADR-0053 (collection generation evidence);
  ADR-0064 (rebuild as a generation); ADR-0083 D-B (the `bm25` sparse vector).

## Context

- A collection's vector config was spelled in one place, `provisioning::collection_setup_puts`: cosine, one shard, one
  replica, the dimension from the CLI. Datatype and HNSW were Qdrant's defaults by omission, so neither was a
  registered setting (§78.1) and nothing could name "the generation a collection belongs to".
- M10-3 (a `turbo4` generation with per-tenant graphs, D1/D2) needs both knobs, and a new name for the new
  collection, before it can exist. This card adds the description and changes no live collection.
- Qdrant 1.19 takes `vectors.datatype` (`float32` | `float16` | `turbo4`) and a collection-level `hnsw_config`
  (`m`, `payload_m`, `ef_construct`) on `PUT /collections/{name}`. `turbo4` keeps only the 4-bit representation; its
  retrieval loss is not measured here (R11-I gates the promotion, M10-3).

## Decisions

### D-A  The knobs are registry entries
`contracts::config_registry` declares five keys (`qdrant.collection.generation_label`, `.datatype`, `.hnsw_m`,
`.hnsw_payload_m`, `.hnsw_ef_construct`) and resolves them into a bounds-checked `CollectionConfig`
(`resolve_collection_config`). Garbage fails loud (§50). `m = 0` without `payload_m` is refused: it would build a
collection with no vector graph at all. Unset keys resolve to Qdrant's own defaults.

### D-B  Defaults are omitted from the body, so the default is the old body
`adapters::qdrant::collection_create_body` starts from `create_collection_body` and adds `vectors.datatype` only when
it is not `float32`, and `hnsw_config` only when it differs from `HnswConfig::QDRANT_DEFAULT`. A deployment that sets
nothing sends exactly the body it sent before, and `collection_generation`'s canonical subset (ADR-0053) is unchanged,
so no recorded activation drifts.

### D-C  `CollectionSpec` = family + dimension + config; the name follows the generation
`CollectionSpec::collection_name` is the bare family name for the unlabelled first generation and
`{family}_{label}` for a labelled one. `provisioning::collection_setup_puts_for(spec)` and `ensure_collection_for(spec)`
use it. The PUT order is the contract: collection, tenant index (`is_tenant`), the other payload indexes, the sparse
vector; no point write is part of the sequence (§17.1). The string entry points (`collection_setup_puts`,
`ensure_collection`) are the default-config case and keep their signatures.

### D-D  A knob change is a new spec, never a mutation
`ensure_collection_for` on a name that already exists changes nothing, whatever its datatype or HNSW. Switching
serving to a new generation stays with `evaluate_switch` (§16.3, M10-3).

## Gates (§80.1; each with an injected-fault record)

| gate | test | injected fault | red run | result |
|---|---|---|---|---|
| G-M10-1 | `crates/adapters/tests/qdrant_contract.rs::spec_body_carries_datatype_and_hnsw_from_config` (and the default-body, label and PUT-order tests beside it) | the body's datatype hard-coded to `float32` | targeted run 39799452136 (red/m10-1-r1 @ add7842) | red on `left: "float32"`, `right: "turbo4"` at the datatype assertion; green is the PR's CI |

## Not done here (owners)

- No binary reads the registry yet: `humaux-maintenance`, the retrieval worker and the gateway still pass a collection
  name and a dimension. The first reader is M10-3's rebuild into a labelled generation.
- `collection_generation` does not include datatype or HNSW in its canonical subset; M10-3 adds them when a second
  generation exists, together with the migration of recorded generations.
- Optimizer and WAL knobs named in the design note have no consumer and no current value; they join the spec with
  the card that sets one.
