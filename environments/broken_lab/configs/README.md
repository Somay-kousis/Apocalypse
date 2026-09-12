# Broken Lab Configurations

One subfolder per boundary (`b1_registry` .. `b9_credentials`), matching
`environments/boundaries/README.md`'s table and `controls/control_spec.yaml`'s
`boundary_dir` field for each rule. Each subfolder holds the misconfigured
artifact a real org would actually audit for that boundary (a YAML manifest,
pod spec, RBAC graph, etc.) - not an ad hoc text file. This replicates the
July 2026 conditions rule-by-rule; checkers read `<this dir>/<boundary_dir>/<config_file>`.
