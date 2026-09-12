# Boundary abstractions (one per boundary, composable)

Brief: "one local abstraction per boundary (9), wired as one composable environment
so #9's cross-boundary check is testable."

Each boundary = one local abstraction (mock service / config surface), composed by BOTH
`broken_lab` and `fixed_lab` (same abstractions, different configs). #9 reads across #6-8.

| # | Abstraction | Owner | broken | fixed |
|---|-------------|-------|--------|-------|
| 1 | package registry / mirror manifest | Junyi | unsealed | hash-attested |
| 2 | egress policy surface | Vikas | allow-all | deny + allowlist |
| 3 | code-exec worker security context | Junyi | root, caps, egress | non-root, no caps |
| 4 | dataset loader policy | Somay | external refs on | external refs off |
| 5 | config pipeline | Somay | templated | parsed as data |
| 6 | pod-spec / IMDS + SA token | Vikas | automount on, IMDS open | locked down |
| 7 | RBAC graph / control-plane reachability | Vikas | worker->API reachable | denied |
| 8 | worker env + alert-log schema | Junyi | reusable authkey | no keys + detection |
| 9 | RBAC/IAM/connector graph (reads 6-8) | Somay | over-broad | scoped + bounded |

TODO(owners): create `environments/boundaries/b<N>_<name>/` per abstraction, referenced by
both labs' docker-compose. Structure only - fill your own boundary dir + config.
