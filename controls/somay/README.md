# Controls - Somay (rules 4, 5, 9)

- **Rule 4** Loader refuses HDF5 external refs. -> `check_hdf5.py` (WORKED EXAMPLE - copy this pattern)
- **Rule 5** No template eval on untrusted config. -> `check_jinja.py` (worked example)
- **Rule 9** Origin-bound credentials - the deep dive. Biscuit-attenuated worker tokens scoped to
  (dataset, job, pod). Replay the `env -> POST env+secrets` exfil step against them; assert the
  stolen token is dead off-origin. This is the fellowship hook - reuses your Pocket-Change primitives.
  -> `check_creds.py`

NOTE (corrected): rule 9 IS cross-boundary and DOES include the `networkx` min-cut. Per the
canonical spec it composes #6-8: (a) credential-scope audit (Biscuit off-origin replay) AND
(b) min-cut reachability over RBAC/IAM/connector configs so no identity's combined reach exceeds
the declared blast-radius bound. See control_spec.yaml depends_on: [6,7,8].
