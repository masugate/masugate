# Reproduction

**Audience:** artifact reviewers. Prerequisite: [Artifact evaluation](artifact-evaluation.md).
**Support boundary:** the required local tier is credential-free; the
Calendar and Stripe profiles are separately optional and do not turn a missing
credential into a core failure.

## Required local tier

The required five-minute demonstration is the exact `procurement` command in the
[README](../README.md#five-minute-local-demonstration). Its timed portion starts
after the [exact one-time setup](artifact-evaluation.md#exact-one-time-setup).
That command produces the Python environment, descriptor-pinned images,
package-lock-bound native npm cache, verified release, and exact environment
file from a clean candidate. The setup may use anonymous network access only
for lock- or digest-bound public inputs. The measured demonstration must run
with network access disabled and no credentials. A missing or mismatched input
is a gate failure, not a skip.

The command validates its generated evidence, tears down its disposable Compose
stack and project-scoped runtime resources, and leaves the evidence under
`/tmp/masugate-five-minute-demo` until the README cleanup command removes that
directory. Its `procurement.json` retains the unsafe stale baseline, the
governed execution, its receipt, and the PSS verdicts; `run-metadata.json`
retains the complete command duration. Run the exact README verifier after the
demo. The clean-candidate execution must complete in less than five minutes;
see [Expected results](expected-results.md) for the observable output.

Source the generated values and enter its clean candidate before running the
local checks:

```sh
. /tmp/masugate-reviewer-setup/reviewer.env
cd "$MASUGATE_CANDIDATE_DIR"
"$MASUGATE_REVIEWER_PYTHON" scripts/build-reference-release.py --verify-only
```

Success is exit status zero. The command validates the machine-readable
reference descriptor and its named local inputs; it does not create a release
directory or contact an external service. A nonzero exit means a named identity,
schema, lock, package, or catalog input disagrees with the descriptor. See
[Expected results](expected-results.md) before diagnosing a failure.

To inspect the available reference-demo scenarios without running one:

```sh
. /tmp/masugate-reviewer-setup/reviewer.env
cd "$MASUGATE_CANDIDATE_DIR"
"$MASUGATE_REVIEWER_PYTHON" scripts/run_reference_demos.py --help
```

The runner exposes `race`, `stale-approval`, `blast-radius`, `receipt`,
`recovery`, and `procurement`. Running another scenario can build or consume
a verified release directory, invoke the local container runtime, and write JSON
evidence below `--outdir`. It is not a no-side-effect command. Use a new,
disposable directory such as `/tmp/masugate-demo`; the default runner path
removes its stack and project-scoped runtime resources, but the selected output
directory remains for inspection. Remove that directory after review. The
explicit `--keep-stack` option is only for debugging and requires manual stack
cleanup.

## Optional Calendar and Stripe profile checks

The connector profiles read configuration identifiers, not raw credentials,
from environment variables and receive the actual secret through a configured
secret handle. A live check is optional. Before any live attempt, confirm the
profile has all required configuration and a disposable provider account:

- Calendar: `MASUGATE_GOOGLE_CALENDAR_ID`,
  `MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_REF`, and
  `MASUGATE_GOOGLE_CALENDAR_OAUTH_SCOPE`.
- Stripe: `MASUGATE_STRIPE_ACCOUNT_ID`, `MASUGATE_STRIPE_CUSTOMER_ID`,
  `MASUGATE_STRIPE_PAYMENT_METHOD_ID`, `MASUGATE_STRIPE_SECRET_REF`,
  `MASUGATE_STRIPE_MERCHANT_IDS`, `MASUGATE_STRIPE_CURRENCY`, and
  `MASUGATE_STRIPE_API_VERSION`.

Never paste a token into a command, source file, terminal transcript, issue, or
evidence record. If the reviewed live harness, a disposable account, network
access, or required configuration is unavailable, record `SKIPPED` with the
missing prerequisite. Do not report it as PASS, and do not use a live-service
check as the sole evidence for a credential-free local property.

The included preflight is safe to run on any machine. It reads only whether the
named configuration values are present; it neither reads a secret value nor
contacts Calendar or Stripe. It reports `SKIPPED` when configuration is absent
or when live execution was not explicitly requested:

```sh
python scripts/optional-connector-preflight.py calendar
python scripts/optional-connector-preflight.py stripe
python scripts/optional-connector-preflight.py both
```

An authorized operator can run the reviewed live harness only with disposable
provider accounts and secret *files* identified by
`MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_FILE` or
`MASUGATE_STRIPE_SECRET_FILE`. For the selected profile, each must name a
regular, nonempty, non-symlink file. The harness checks that prerequisite
without reading its contents, and reports `SKIPPED` without network access
when it is absent or invalid. It reads the file only after both flags below are
present. It creates and cancels one disposable Calendar event,
or creates and cancels one 50-cent Stripe test-mode PaymentIntent, in the same
invocation. It prints no token or external identifier.

```sh
python scripts/optional-connector-preflight.py calendar --execute-live --confirm-side-effects
python scripts/optional-connector-preflight.py stripe --execute-live --confirm-side-effects
python scripts/optional-connector-preflight.py both --execute-live --confirm-side-effects
```

These are external service operations, are not part of the credential-free
release gate, and were not run for this candidate. Obtain the required
authorization and use only disposable provider resources before executing
them. A failed cleanup is an operational incident: preserve the nonsecret
error output and remove the provider object manually before retrying.

## Cleanup

Stop any demo stack, remove its disposable output directory, and revoke or
rotate any test-only secret according to the service owner’s procedure. Never
delete an existing database, user directory, or mount as part of cleanup.

Version: `0.1.1` (research preview). Next: [Expected results](expected-results.md).
