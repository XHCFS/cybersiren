# JOSS Submission Guide — CyberSiren

Everything needed to submit `CyberSiren` to the Journal of Open Source Software
(<https://joss.theoj.org>). JOSS reviews the **software repository**, not research claims.

## AI usage disclosure (paste into the submission / review thread)

> The authors used Claude (Anthropic) for code and test scaffolding, documentation
> drafting, and copy-editing. All architectural decisions, the system design, the
> machine-learning methodology, and the experimental work were made and carried out by the
> human authors, who reviewed and take full responsibility for all outputs. No AI was or
> will be used in the author–reviewer review conversation, per JOSS policy.

## Readiness checklist (JOSS review criteria)

| Requirement | Status |
|---|---|
| Public open-source repository | ✅ <https://github.com/XHCFS/cybersiren> |
| OSI-approved **LICENSE** | ✅ MIT (`LICENSE`) — *confirm with all co-authors / the institution* |
| `paper.md` (summary + statement of need + references) | ✅ at repo root |
| `paper.bib` | ✅ at repo root |
| **Installation** instructions | ✅ README "Quick Start" + Docker Compose |
| **Example usage** | ✅ README demo (`make demo …`), web UIs |
| **Automated tests** | ✅ 113 Go + 5 Python tests, run in CI (`.github/workflows/ci.yml`) |
| **Community guidelines** (contribute / report / support) | ✅ `CONTRIBUTING.md` |
| Statement of need | ✅ in `paper.md` |
| AI usage disclosure | ✅ above |

## Remaining manual steps (must be done by a human author)

1. **Confirm the LICENSE choice** with all co-authors and the XHCFS organization. MIT is
   the default; swap to Apache-2.0 if a patent grant is wanted.
2. **Tag a release** of the repository (e.g., `v1.0.0`) so there is a citable version.
3. **Archive the tagged release on Zenodo** (or figshare) to get a DOI. Connect the GitHub
   repo to Zenodo, then publish the release; Zenodo mints an archive DOI. JOSS requires this
   at acceptance.
4. **Submit** at <https://joss.theoj.org/papers/new>: provide the repository URL, the
   version/tag, and the Zenodo DOI. Paste the AI usage disclosure when prompted (or in the
   review thread).
5. **During review**, respond to the reviewer/editor **yourself** on the GitHub review
   issue — JOSS prohibits AI in the author–reviewer conversation.

## Honest expectation

JOSS is achievable and the AI question is a non-issue with the disclosure above. The real
gate is JOSS's **"substantial scholarly effort"** criterion: the editor judges whether this
is research software for the community rather than a one-off project. Your strongest
evidence is the associated preprint (arXiv:2606.21690), the released datasets and the
leakage-controlled benchmark, the full test suite and CI, and the end-to-end instrumentation.
The soft spot is the absence of external adopters; the `paper.md` statement of need is
written to lean on the reusable artifacts rather than on adoption.
