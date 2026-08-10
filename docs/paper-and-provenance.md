# Paper and provenance

**Audience:** researchers and reviewers. Prerequisite: [Concepts](concepts.md).
**Boundary:** this release records implementation provenance; it does not
publish a historical dataset or claim external results beyond the cited paper.

The MasuGate repository begins with root commit 6b3852ecb70bd55cb22bf78769028b9b52af9735,
imported from the selected source revision 1373f5507c1680c60a7700d8a6c26a8b4d3fb025.
The checked-in
[`release/reference-release.json`](../release/reference-release.json) names the
release identity, package identities, target platform, and release
input roles.

Generated release provenance distinguishes the immutable source revision from
the public tree revision used to produce an artifact. When a release is built
from a separately recorded source snapshot, both identities remain explicit;
the release-tree revision is never presented as the source revision.

The accompanying paper, [*Stateful Governance for Concurrent Agentic Systems*](https://arxiv.org/abs/2608.02764), is the preferred scholarly citation for
this release. The currently indexed record may still use the historical name
Provenact; a terminology rename to MasuGate has been submitted for announcement
on 2026-08-11. This establishes historical research provenance only. Do not
infer that an implementation path or release descriptor broadens the paper's
stated experimental or deployment boundary.

Citation metadata is in [`CITATION.cff`](../CITATION.cff). See the
repository-root [provenance note](../PROVENANCE.md) and
[trademark policy](../TRADEMARKS.md).

Version: `0.1.0` (research preview). Next: [Artifact evaluation](artifact-evaluation.md).
