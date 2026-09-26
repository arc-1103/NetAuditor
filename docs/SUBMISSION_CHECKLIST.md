# SIH26155 submission checklist

The problem statement requests a source-code link, setup README, architecture
document (maximum two pages), demo video (maximum two minutes), and technical
presentation (maximum five slides).

## Upload package

- [ ] Repository is public or accessible to evaluators and points to the tested commit.
- [ ] Root README quick start is tested on the actual presentation laptop.
- [x] Architecture is exported as `submission/NetAudit_SIH26155_Architecture.pdf` (validated: two pages).
- [x] Presentation is rendered as `submission/NetAudit_SIH26155_Technical_Presentation.pptx` (validated: five slides).
- [ ] Demo video is at most two minutes and shows upload → evidence → safe remediation → report.
- [ ] Repo URL is present; replace the pending demo-video field after uploading the final recording.
- [ ] No `.env`, credentials, private device configurations or personal data are committed.
- [ ] `./scripts/verify.sh` or the GitHub Actions workflow is green on the submitted commit.
- [ ] Venue fallback (`cd frontend && npm run demo`) is tested without internet.

## Claims to keep precise

Say **"CIS-inspired 11-control prototype policy"**, not "CIS certified." Say
**"architecture supports additional frameworks/vendors"**, not "supports every
vendor today." Demonstrate Cisco and Fortinet. Present Juniper, Palo Alto,
bulk-upload UI and complete CIS/NIST/STIG/ISO content as next milestones.

## Two-minute video beat sheet

- **0:00–0:15:** heterogeneous-network problem and one-sentence solution.
- **0:15–0:45:** upload insecure Cisco fixture; identify/redact/normalize.
- **0:45–1:15:** show line-level finding and deterministic OPA decision.
- **1:15–1:40:** generate remediation; explain preflight and human approval.
- **1:40–1:55:** open evidence report and mention offline deployment.
- **1:55–2:00:** team name, repository link and closing impact statement.

Do not spend video time on login, Docker startup, source-code scrolling or
optional features outside the reliable demo path.
