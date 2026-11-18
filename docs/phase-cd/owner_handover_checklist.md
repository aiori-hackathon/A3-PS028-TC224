# AIORI-3 PS-028 Submission Handover Checklist (Owner Actions & Merge Procedure)

- **Team**: AlgoRhythm (TC224)
- **Problem Statement**: PS-028 (Happy Eyeballs IPv4/IPv6 Fallback Measurement)
- **Authoritative Integration Feature Branch**: `fix/phase-e-bundle-timeline-mapping`
- **Final Submission Branch**: `main` (commit `fc4fef7df5b9638dd438e6b4acaadf4d219b3e26`)
- **Historical Derivation Branch**: `regional/ps028-phase-cd`
- **Protected P0 Acceptance Commit**: `176f688bacb5858fcc0daedb454200918e427f3f` (tag: `ps028-p0-accepted-2026-11-14`)
- **Submission Documents**: `PS028_Hackathon_Submission_Presentation.pdf` & `PS028 Detailed Analysis & Report PDF.pdf`
- **Authoritative Campaign**: `ps028-a10-live-20261030-01` (705 cryptographically sealed files)
- **Remote CI Run**: Run ID [`43733419747`](https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43733419747) (SUCCESS, 3/3 jobs passed)

> [!IMPORTANT]
> **Owner Actions Only (Rule R11 Non-Negotiable):**
> These administrative actions MUST be performed manually by the repository owner in the GitHub web interface and hackathon submission portal. The autonomous assistant is strictly barred from modifying repository settings, collaborators, visibility, or merging directly into `main`.

---

## 1. Technical Completion Record (Automated & Tested)

The technical preparation on feature branches is fully validated and reproducibly established:

- [x] **P0 Acceptance Baseline**: Protected tag `ps028-p0-accepted-2026-11-14` verified as ancestor of HEAD at `176f688bacb5858fcc0daedb454200918e427f3f`.
- [x] **Campaign Integrity**: 705 historical campaign files verified bit-for-bit matched against `historical_integrity_before.sha256`.
- [x] **Automated Test Suite**: 966 unique automated tests validated in remote CI (842 lab + 93 integration + 31 frontend; 100% PASS, 0 failures, 0 errors, 0 skips); local security and provenance hardenings expanded to 872 lab tests (996 total automated tests).
- [x] **Separate Quality Gates**: 16 frontend smoke checks and 14-stage / 242-assertion genuine Chromium browser acceptance suite passing.
- [x] **Remote Continuous Integration**: GitHub Actions CI Run #3 ([`43741695912`](https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43741695912), commit `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3`) succeeded across all 3 jobs (`python-tests`, `frontend-validation`, `artifacts-validation`) in 2m 8s with 966 tests; preceding Run #2 ([`43733419747`](https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43733419747), 962 tests) preserved.
- [x] **Submission Artifacts**: Presentation PDF (`PS028_Hackathon_Submission_Presentation.pdf`, 11 pages, 207,985 bytes) and Technical Report PDF (`PS028 Detailed Analysis & Report PDF.pdf`, 22 pages, 463,831 bytes in CI / 463,864 bytes local; 100% stream-matching) generated and verified.
- [x] **Prototype Replay**: Standalone replay utility operational (`lab/demo_replay.py`) with canonical Happy Eyeballs pseudocode.
- [x] **Phase D Archival Status**: Phase D empirical live sweeps permanently removed from delivery plan by owner decision; analytical simulation models preserved offline in `lab/derived/phase-d/`. Requirements #16 and #17 remain PARTIAL.
- [x] **Partner Package Prepared**: Replication runbook and manifest prepared for canonical 280-trial core matrix; scheduled as final separate milestone (Requirement #20 PENDING).

---

## 2. Manual Owner Actions (Pending Owner Execution)

The following actions require human operator execution. Do not claim portal upload, collaborator validation, or judge access is complete without verified evidence:

1. **Confirm Judge and Collaborator Access**:
   - Navigate to `https://github.com/aiori-hackathon/A3-PS028-TC224/settings/access`.
   - Verify that event judges and designated team collaborators have appropriate read/review permissions.
2. **Confirm Repository Visibility**:
   - Confirm repository visibility meets organizer requirements (the repository is currently public; verify whether public or private visibility is expected by the evaluation panel).
3. **Upload Presentation Slide Deck**:
   - Upload `PS028_Hackathon_Submission_Presentation.pdf` (11 pages matching `Proposed-structure-hackathon.pdf` geometry) to the organizer submission portal.
4. **Upload Technical Report**:
   - Upload `PS028 Detailed Analysis & Report PDF.pdf` (22 pages) to the organizer submission portal.
5. **Submit Demonstration Video**:
   - Submit the demonstration video URL (documented in `README.md`: `https://youtu.be/LYngp7dzoRI?si=1mPrapHizazV41zB`).
6. **Preserve Verified CI Evidence**:
   - Record the verified GitHub Actions Run #3 URL (`https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43741695912`) and artifact link (`ps028-submission-artifacts`, ID `14172830625`), along with preceding Run #2 (`43733419747`).
7. **Submit Canonical Repository URL**:
   - Submit `https://github.com/aiori-hackathon/A3-PS028-TC224` as the canonical repository after the final merge to `main`.

---

## 3. Final PR and Main Merge Procedure (DOCUMENT ONLY — DO NOT EXECUTE NOW)

The final submission branch must ultimately be `main`. The current integration branch `fix/phase-e-bundle-timeline-mapping` is an active development and integration feature branch.

When all planned work is finished, the final integration to `main` must strictly follow this 14-step sequence:

1. **Complete Every Planned Feature Task**: Confirm that all required features, tests, and documentation are complete on feature branches.
2. **Complete Partner Replication Milestone**: If retained by the owner as a submission prerequisite, execute the independent 280-trial partner replication campaign per `docs/phase-cd/partner_replication_runbook.md`.
3. **Preserve Authentic Partner Evidence**: Verify cryptographic checksums of external partner evidence and update `docs/phase-cd/partner_replication_manifest.json` from `PENDING` to `VERIFIED`.
4. **Freeze the Integration Branch**: Announce code freeze on `fix/phase-e-bundle-timeline-mapping`.
5. **Reconcile Feature Commits**: Integrate any final feature commits into `fix/phase-e-bundle-timeline-mapping`.
6. **Compare Against Latest `main`**: Run `git diff origin/main...HEAD` to inspect the full cumulative diff.
7. **Open Final Pull Request**: Open a formal GitHub PR targeting `base: main` from `head: fix/phase-e-bundle-timeline-mapping`.
8. **Inspect Entire PR Diff**: Conduct an exhaustive line-by-line review of the pull request changes.
9. **Require Successful CI on PR**: Ensure all 3 GitHub Actions CI jobs (`python-tests`, `frontend-validation`, `artifacts-validation`) pass on the PR branch.
10. **Verify Submission PDFs and Documentation**: Check that the generated presentation and technical report PDFs match all submission requirements.
11. **Obtain Explicit Owner Authorization**: Obtain written confirmation from the repository owner to merge.
12. **Merge into `main`**: Perform the merge into `main` using the standard GitHub merge interface.
13. **Verify Resulting `main` Commit and CI**: Pull the updated `main` branch locally, verify git log/provenance, and verify that post-merge CI passes on `main`.
14. **Final Submission**: Use the canonical repository URL `https://github.com/aiori-hackathon/A3-PS028-TC224` (now reflecting `main`) as the authoritative submission link.

> [!CAUTION]
> **Strict Instruction**: Do NOT execute this final merge procedure now. Do NOT open the final PR to `main` now. All active work remains on `fix/phase-e-bundle-timeline-mapping`.
