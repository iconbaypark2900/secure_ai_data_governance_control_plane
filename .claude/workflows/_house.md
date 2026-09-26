# Workflow house rules

Shared context for every workflow in this directory. Each script inlines its own copy
(scripts cannot read the filesystem), so edit both if you change something here.

- `make check` is the gate: ruff check, ruff format --check, mypy on control_plane/, pytest.
  682 tests pass in ~14s on SQLite. Do not leave them failing.
- ruff line-length 100, target py312. mypy disallow_untyped_defs on control_plane/.
- Fail closed. Deny by default. An error on the decision path is a deny, never an allow.
- ADR 0006: sensitive values never reach durable storage — labels, offsets, masked previews
  and keyed digests only.
- ADR 0010: declare only what is implemented.
- Detectors pair a pattern with a structural check. A bare regex is not a detector here.
- New load-bearing decisions get an ADR in docs/adr/, numbered from 0017.
- Commits must carry no Co-Authored-By, Claude-Session, or any AI/assistant trailer.

Invoke by name from inside the repo, or by path from anywhere:

    Workflow({ name: "fix-obligation-gap" })
    Workflow({ scriptPath: ".claude/workflows/fix-obligation-gap.js" })

Every workflow accepts `args.repo` to override the repository path.
