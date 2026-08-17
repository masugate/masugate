# Troubleshooting

**Audience:** reviewers and developers. Start with [Expected results](expected-results.md).
**Support boundary:** diagnose the observed prerequisite; do not weaken or
relabel a failed gate.

| Symptom | Check | Resolution |
|---|---|---|
| Descriptor check fails | Read the reported path and compare it with `release/reference-release.json` | Restore the exact reviewed input; do not edit the descriptor to fit a drifted environment |
| Python cannot import a package | Confirm the documented Python environment and package installation | Recreate the clean reviewed environment; do not add `PYTHONPATH` to a release command unless the command explicitly requires source execution |
| Node workspace check fails | Confirm the locked Node/npm environment and run from the workspace root | Leave the retained candidate and use the [documented safe cleanup sequence](artifact-evaluation.md#current-candidate-limitations) to remove `/tmp/masugate-reviewer-setup`, then re-run the exact [one-time reviewer setup](artifact-evaluation.md#exact-one-time-setup); do not fall back to an unpinned registry install |
| Container demo cannot start | Check that the local container runtime is available before running a scenario | Record the unavailable runtime; do not substitute a host-side effect for the contained reference workflow |
| PostgreSQL endpoint is unavailable | Confirm the selected disposable reference stack and its lifecycle | Do not point the command at a production or shared database |
| Calendar or Stripe credentials are absent | Check the optional profile configuration | Record `SKIPPED`; never print a token or secret-handle content |
| A cited claim-evidence test is absent | Compare the path against the current tree | Treat this as the documented claim-evidence blocker, not as evidence that the claim passed |

For protocol failures, compare the response with the closed schema in
[`protocol/schemas/`](../protocol/schemas/). For connector isolation failures,
start with [Connectors](connectors.md). For an action lifecycle question, use
the [walkthrough](governed-action-walkthrough.md).

Version: `0.1.1` (research preview). Next: [Testing](testing.md).
