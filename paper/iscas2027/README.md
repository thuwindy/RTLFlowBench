# G12-RTL paper source companion

This additive source companion accompanies the CriticRTL ISCAS 2027 submission. G12-RTL is the paper name for Golden-12. Original `golden12`, `chipflow` and schema identifiers remain unchanged so historical source bytes stay verifiable. The repository's existing candidate preview is unchanged.

This is a **partial source release**, not a frozen benchmark, full runtime replay, complete scorer package or public SOTA claim. The paper evaluates/calibrates G01–G07; G08–G12 remain catalog tasks outside the paper evaluation. Missing trust, resource or execution evidence stays unavailable, never zero.

| Directory | Included | Boundary |
|---|---|---|
| `sources/v7` | Execution-bound benchmark controller, baseline, native adapters, submission/scope/resource gates and schemas | Framework backend, model service, upstream workflow trees and images are separate dependencies |
| `sources/v8-overlay` | Exact benchmark-side v8 delta over v7 | Framework-side v8 deltas are not included |
| `sources/r1-v16-overlay` | Exact R1 benchmark-side changes over v8 | This does not supply the whole 1,129-file v16 runtime |
| `public-tasks/r1` | Exact four task public packets, 80 files; each matches 30 R1 attempt inputs | Seeded starting designs, candidate outputs, private tests and model conversations are excluded |
| `evaluator-helpers` | G03–G05 verdict/scoring/neutral-result projection code and schemas | No hidden pools, reference solutions, testbenches or complete runner/environment closure |
| `dependencies` | Upstream task commits, archive hashes, projection allowlists and notices | Pin metadata is not a license grant or a reproduced build |
| `provenance` | Path-free source/experiment/scorer bindings and omissions | Historical full manifest hashes are identifiers, not claims all bound files are included |

Run this offline check from this directory:

```sh
python3 verify.py
```

It checks declared source bytes and membership. It does not import the research runtime, invoke a model, execute EDA, or classify RTL correctness. The containing repository also has its own public preview verification command.

## Historical versions

E1 has 39 attempts bound to core v7, 6 to v8 and 45 to separately bound native workflows. E3 has 180 core-v7 attempts and 90 native-workflow attempts. R1 uses its own v16 preparation identity across 120 attempts. These cohorts and source identities must not be pooled or relabeled. Native image/runtime digests and original core manifest digests are in `provenance/experiment-source-bindings.json`.

Apply overlays only in a fresh reconstruction workspace: v7 plus v8 for E1 v8, and v7 plus v8 plus the R1 overlay for R1 benchmark-side sources. The framework-side files are still required. Neither the current development workspace nor these overlays alone establish executable closure. Source selection requires the original attempt manifest and all dependency hashes.

All files listed in `provenance/source-manifest.json` are byte-identical copies with their original SHA-256. A source containing a private host path was omitted rather than edited. `post_run_source_changes` is empty for these copies. Publication metadata and documentation are newly authored projections, not historical execution receipts.

## Reconstructing inputs and evaluation

Fetch upstream task sources using `dependencies/task-sources.json` into a fresh content-addressed store outside Git. Verify archive and declared file hashes, retain required notices, then create only each task's allowlisted repository projection. Do not fetch branch HEAD. G01/G02 blank scaffolds do not receive upstream reference RTL. G12's intentionally withheld contract requires its separate deterministic comment-only projection and is outside this paper's evaluation.

G05's historical license URL names a `COPYING` file absent from that frozen archive. The original `picorv32.v` embeds its ISC notice and the README identifies ISC; retain those notices and record any reviewed correction as a new projection. Do not fabricate or silently replace the historical lock.

A functional evaluator needs the complete task-specific scorer source, test assets, locked registry, source-intake projections and pinned OCI/toolchain. The scorer manifests each bind 3,312 files; the helpers here are a subset. G03, G04, G05 and R1 G06 have distinct scorer identities. G06 R1 has a prospective budget projection, not an amendment of earlier evaluator receipts. See `provenance/scorer-bindings.json`. The full hidden evaluation package and environment reconstruction recipe are not supplied by this release; full E1/E3/R1 execution cannot be reproduced from this repository alone.

Use separate trusted grading and untrusted workflow environments. Only public task input and its approved repository projection enter the workflow. Terminate the workflow before grading the immutable submitted artifact. Keep private test plans, reference designs and grading data outside workflow and submitted-DV mounts. The word `private` describes this evaluation boundary; it does not mean every evaluator algorithm is legally proprietary.

Independent runtime reconstruction also needs the exact CriticRTL/DeerFlow backend, native baseline source snapshots and overlays, package/wheel hashes, Python and EDA versions, OCI build inputs, provider policy and role budgets. An image digest or a local `FROM sha256:...` line is not a publicly fetchable build recipe. No environment closure or complete cross-host replay is claimed here. Historical MAGE metadata records inconsistent MIT LICENSE versus Apache package classifier declarations; preserve upstream notices and treat its rights separately.

## Rights and publication scope

The root `NOTICE.md` and `TOOLS_LICENSE.txt` continue to govern the existing preview. Do not extend that limited MIT helper/test grant to the imported packet corpus, schemas or upstream RTL. Task rights/admission receipts remain unsigned and unchanged. This publication does not declare them independently admitted or rights-cleared.

`DEERFLOW_LICENSE.txt` preserves the original Bytedance/DeerFlow MIT copyright and license for covered copied framework-derived tools. It is not a replacement license for upstream SHL-0.51, ISC, Apache-2.0 or MIT task material and does not grant a blanket license over the imported corpus. Upstream dependencies retain their own notices and terms. New publication metadata and the verification helper carry no additional license grant beyond the repository's stated scope.

Excluded material includes credentials, private machine paths, raw provider responses/conversations, model reasoning, proprietary documentation/skill material, hidden evaluator pools, reference solutions, calibration fixtures, waves, archives and raw execution logs. Original research evidence remains preserved separately. Public visible testbenches in the task packets are intentionally visible; they are not hidden evaluation evidence.
