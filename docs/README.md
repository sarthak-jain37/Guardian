# Guardian documentation

These guides describe the merged implementation. The local pilot has completed
verified initial Role narrowing; independent lab acceptance, live recovery and
held-out evaluation are separate outstanding gates.

| Start here | What it covers |
| --- | --- |
| [Project overview](../README.md) | Purpose, architecture, repository layout and supported scope |
| [Demo runbook](demo-runbook.md) | Prepared laptop, clean-host setup, exact review and outcome checks |
| [Project report](project-report.md) | Dated implementation/results, real demo follow-up and remaining acceptance |
| [Analysis and review](analysis.md) | Scoped intake, inference worker, reports and fresh/context revisions |
| [Governance](governance.md) | Credentials, decisions, durable delivery, holds and retired mutation routes |
| [Execution and recovery](execution.md) | Independent preparation, conditional patch, verification and exact consent |
| [Evidence and archives](evidence.md) | Audit usage, identity, coverage, collection progress and retention |
| [Telemetry](telemetry.md) | Hubble/Tetragon exports, pod evidence, advisory assessments and alerts |
| [Model runtime](models.md) | Ollama default, optional providers, model identity and resource limits |
| [Deployment](deployment.md) | Helm, identities, persistent storage, backup/restore and model connectivity |
| [Evaluation](evaluation.md) | Frozen deterministic/LLM comparison and the retained safety failure |
| [Attack/failure catalog](attack-catalog.md) | Reproducible cases with live versus recording evidence clearly separated |
| [Release responsibilities](release-responsibilities.md) | Continuing operator, reviewer, custodian and acceptance responsibilities |
| [LangGraph module](../agents/guardian/README.md) | Component boundaries and development commands |

`release/*.json` contains dated measurements, including unsuccessful results and
the original pre-approval pilot snapshot. These are historical evidence, not
mutable current cluster status; see the project report for subsequent results.
`../contracts/decisions/` records design decisions at their original delivery
points. Their historical pending statuses do not override current operational guides.

Private study notes, generated presentations, credentials and raw pilot artifacts
belong in ignored local directories. The old phase tracker, superseded Word report
and obsolete slide outline have been removed from the maintained documentation.
