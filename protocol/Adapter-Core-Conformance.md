# Adapter-core conformance kit

> Reader and reviewer navigation: [Documentation map](../docs/README.md).

The included TypeScript adapter core is a framework-neutral replacement runtime
over the public MasuGate SDK:

- TypeScript: `@masugate/adapter-core` in [`adapters/typescript`](../adapters/typescript/)

It consumes the versioned
[`adapter-core-conformance.json`](examples/adapter-core-conformance.json)
scenario corpus. It fixes a governed-route manifest, trusted host invocation,
declared model arguments, canonical JSON bytes, and the complete conformance
matrix: canonical bytes, forged-field rejection, exact retry, changed content,
distinct calls, every lifecycle state, pending resume/terminal reads, locator
mismatches, and capability gates. A binding supplies trusted principal/source
context and a scenario-indexed public-client factory; model input supplies only
the declared argument values. The package ships a copy and exports its fixture
loader, runtime factory, canonical-byte assertion, and an async conformance
runner that emits the version and passed-case IDs.

The conformance suite proves that a runtime:

- rejects model-supplied identity, owner, pending, and locator fields;
- preserves an exact retry's one operation while giving distinct trusted calls
  distinct operation identities;
- rejects changed content for the same trusted invocation;
- returns every GAP lifecycle as a replacement-only presentation, including
  `outcome_unknown`, with no host-native-effect permission or automatic new
  action retry; and
- resumes and reads terminal pending work only through the complete original
  locator, rejecting a pending, cancellation, terminal, or receipt response
  for a different operation; and
- gates optional control-plane operations on the adapter's declared
  capabilities while allowing an empty capability declaration for submit-only
  bindings.

The scenario factory makes nonterminal/pending cases reproducible without
coupling the package to one policy fixture. The TypeScript suite starts the
real `masugated` application in a short-lived Python process and reaches it
through the published TypeScript client; it is not a Node HTTP mock. The core
does not carry
host context extraction, credentials, policy, pending authority, connector
credentials, effects, or host-framework imports; those remain binding-owned
responsibilities.
