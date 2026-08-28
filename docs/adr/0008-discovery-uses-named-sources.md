# 0008 — Discovery runs against named, server-side sources

**Status:** accepted

## Context

The adapters could enumerate and sample from the day they were written, and
nothing ever called them. The catalog could only be filled in by hand, which
meant the asset nobody remembered to register — the one that leaks — stayed
invisible to the control plane.

Making discovery reachable raises a question the rest of the system does not
have: discovery needs credentials for *another* system. Everything else operates
on data the caller already sent.

## Decision

Sources are configured once, server-side, and referred to by name:

```yaml
sources:
  - name: warehouse
    adapter: postgres
    dsn: ${WAREHOUSE_DSN}
    exclude: ["pg://audit.*"]
```

`cpctl catalog discover warehouse` and
`POST /v1/catalog/sources/warehouse/discover` both name the source. No
connection string ever appears in an API request body.

Secrets interpolate from the environment, so the file is safe to commit and the
credentials live wherever the deployment already keeps them.

Four supporting choices:

**Sampling is off by default.** Registering an asset reads metadata; sampling
reads records. Those are different acts and the second should be chosen, after a
`--dry-run`, not inherited.

**`exclude` wins over `include`.** It is the control that keeps a scanner out of
an audit table, a secrets table, or anything under legal hold — and a control
that can be overridden by a broader `include` is not a control.

**One asset's failure is not the run's failure.** A table the credentials cannot
read must not stop the other four hundred from being catalogued. Errors are
collected and reported per asset; only failing to reach the source at all fails
the run.

**One audit record per run, not per asset.** Registering four hundred tables is a
single operator action, and a chain that turns it into four hundred entries
buries the changes a reader came to find. The record names the source, the
counts, the label distribution, and the URNs that became classified — capped —
because those are the posture change worth reading.

## Alternatives

**Credentials in the request body.** Simplest to build and it puts a production
DSN into request logs, proxy buffers, and browser history. The whole point of a
governance control plane is not being the place sensitive material accumulates.

**A source per API call, stored transiently.** Same exposure, plus state.

**Discover everything automatically on a schedule.** Attractive, and the wrong
default: an unattended job that samples production tables is a data access
pattern nobody approved. The pieces are here for anyone who wants to run it from
cron with an explicit configuration.

## Consequences

Sources must be configured before discovery can run, which is a step. `cpctl
catalog discover --adapter postgres --dsn ...` exists for ad-hoc use, where the
operator already holds the credential and is typing it into their own terminal.

An unset environment variable leaves a source listed but unusable rather than
breaking the whole file. A file with four sources should still load when only two
of their variables are set in the process you are standing in, and the failure
belongs at the moment someone tries to use the unconfigured one — where it can
name what is missing.

Discovery over HTTP is synchronous and bounded by `max_assets`. A run across a
large warehouse belongs on the CLI, which is not sitting behind an HTTP timeout.
A background job runner would remove that limit and is not worth its own
subsystem yet.

Only `postgres` and `qdrant` can back a source. The MCP and LibreChat adapters
map identifiers and build decision requests; there is nothing to enumerate
without a live client session. Naming one as a source is refused with that
explanation rather than accepted and silently doing nothing.
