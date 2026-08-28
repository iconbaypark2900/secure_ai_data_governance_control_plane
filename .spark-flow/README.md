# Liaison local memory — secure_ai_data_governance_control_plane

This directory (`.spark-flow/`) is **Liaison local memory**. It is gitignored and never committed.

## Key files

| File | Purpose |
|------|---------|
| `project_profile.yaml` | Routing-ready context: validation commands, risks, recommended agents |
| `memory/project_phase.json` | Lifecycle status + maturity phase history |
| `tasks/<task-id>/` | Per-task reporter filesystem (BRIEF, CONTEXT, APPROVALS, etc.) |
| `current/` | Active task pointer |

## Reporter flow

```bash
cd /home/iconbaypark2900/dataScience/secure_ai_data_governance_control_plane
liaison init <task-id> "<one focused goal>"
liaison snapshot --show
# Hermes (or specialist) does the work
liaison attach hermes --text "<report>"
liaison approve-artifact .spark-flow/tasks/<task-id>/outbox/<artifact>
liaison decision "<operator choice>"
liaison validate --profile python
liaison gate --show
liaison close-task --summary "<outcome>"
```

## Current validation profile

`python` — see `project_profile.yaml` for commands.

## Project docs

- [docs/LIAISON_PROJECT_BRIEF.md](../docs/LIAISON_PROJECT_BRIEF.md)
- Operator docs: `~/spark/docs/local-agents/`
