"""``cpctl`` -- the operator's command line.

Talks to the database directly rather than through the HTTP API, so it works
before the service is running and while it is broken: bootstrapping a schema,
loading a policy set, issuing the first key, and verifying the audit chain are
all things you need most when the API is the thing that is down.

    cpctl db upgrade
    cpctl seed
    cpctl key issue --name gateway --scope decide --scope catalog:read
    cpctl serve
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from control_plane.adapters.registry import (
    SourceConfig,
    SourceConfigError,
    SourceRegistry,
    UnknownSource,
)
from control_plane.audit.chain import AuditEvent
from control_plane.audit.service import AuditService
from control_plane.auth.keys import Scope, normalise_scopes
from control_plane.auth.service import ApiKeyService
from control_plane.catalog.discovery import DiscoveryService
from control_plane.catalog.service import CatalogService
from control_plane.classification.scanner import scan_structured, scan_text
from control_plane.config import get_settings
from control_plane.db import create_all, dispose_engine, session_scope
from control_plane.pdp import PolicyDecisionPoint
from control_plane.policy.model import Policy, PolicySet
from control_plane.policy.store import PolicyStore
from control_plane.schemas.decision import DecideRequest

app = typer.Typer(
    name="cpctl",
    help="Operate the Secure AI Data Governance Control Plane.",
    no_args_is_help=True,
    add_completion=False,
)
db_app = typer.Typer(help="Schema management.", no_args_is_help=True)
policy_app = typer.Typer(help="Author and inspect policies.", no_args_is_help=True)
key_app = typer.Typer(help="Issue and revoke API keys.", no_args_is_help=True)
audit_app = typer.Typer(help="Read and verify the audit chain.", no_args_is_help=True)
catalog_app = typer.Typer(
    help="Populate the catalog from the systems that hold data.", no_args_is_help=True
)
app.add_typer(db_app, name="db")
app.add_typer(policy_app, name="policy")
app.add_typer(key_app, name="key")
app.add_typer(audit_app, name="audit")
app.add_typer(catalog_app, name="catalog")

console = Console()
error_console = Console(stderr=True)

EFFECT_STYLE = {
    "allow": "green",
    "deny": "red",
    "require_approval": "yellow",
}


def run(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run an async command and always dispose of the engine."""

    async def wrapper() -> Any:
        try:
            return await coro
        finally:
            await dispose_engine()

    return asyncio.run(wrapper())


def fail(message: str) -> NoReturn:
    """Print an error and stop.

    Typed NoReturn so that a type checker -- and a reader -- knows the code after
    a `fail()` call is unreachable.
    """
    error_console.print(f"[bold red]error:[/] {message}")
    raise typer.Exit(code=1)


def load_document(path: Path) -> Any:
    if not path.exists():
        fail(f"{path} does not exist")
    text = path.read_text()
    if path.suffix in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    return json.loads(text)


# --------------------------------------------------------------------------- #
# db
# --------------------------------------------------------------------------- #


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Run Alembic migrations up to head."""
    from alembic import command
    from alembic.config import Config

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    console.print("[green]schema is at head[/]")


@db_app.command("create")
def db_create() -> None:
    """Create tables directly, skipping migrations.

    For a throwaway local database. It does not install the append-only trigger
    on the audit table, so use `db upgrade` for anything you care about.
    """
    run(create_all())
    console.print("[green]tables created[/] [dim](no audit trigger -- use `db upgrade`)[/]")


@db_app.command("status")
def db_status() -> None:
    """Report connectivity and row counts."""

    async def inner() -> None:
        from sqlalchemy import func, select

        from control_plane.models import (
            ApiKey,
            AuditRecordRow,
            DataAsset,
            DecisionRecord,
            PolicyRecord,
            Principal,
        )

        async with session_scope() as session:
            table = Table("table", "rows", title="Control plane")
            for label, column in (
                ("policies", PolicyRecord.id),
                ("data_assets", DataAsset.id),
                ("principals", Principal.id),
                ("decisions", DecisionRecord.id),
                ("audit_records", AuditRecordRow.seq),
                ("api_keys", ApiKey.id),
            ):
                count = (await session.execute(select(func.count(column)))).scalar_one()
                table.add_row(label, str(count))
            console.print(table)

    settings = get_settings()
    console.print(f"[dim]{_safe_dsn(settings.database_url)}[/]")
    run(inner())


# --------------------------------------------------------------------------- #
# seed
# --------------------------------------------------------------------------- #


@app.command("seed")
def seed(
    policies: Annotated[Path, typer.Option(help="Policy set file.")] = Path("seed/policies.yaml"),
    catalog: Annotated[Path, typer.Option(help="Catalog file.")] = Path("seed/catalog.yaml"),
    prune: Annotated[bool, typer.Option(help="Remove stored policies not in the file.")] = False,
) -> None:
    """Load the reference policy set and catalog."""

    async def inner() -> None:
        async with session_scope() as session:
            policy_set = PolicySet.model_validate(load_document(policies))
            result = await PolicyStore(session).sync(
                policy_set.policies, actor="cpctl seed", prune=prune
            )
            console.print(
                f"policies: [green]{len(result['created'])} created[/], "
                f"[yellow]{len(result['updated'])} updated[/], "
                f"{len(result['unchanged'])} unchanged, "
                f"[red]{len(result['removed'])} removed[/]"
            )

            document = load_document(catalog)
            service = CatalogService(session)
            for entry in document.get("assets", []):
                asset, _ = await service.upsert_asset(
                    entry["urn"],
                    name=entry.get("name"),
                    kind=entry.get("kind"),
                    owner=entry.get("owner"),
                    description=entry.get("description"),
                    attributes=entry.get("attributes"),
                )
                for label in entry.get("classifications", []):
                    await service.set_classification(
                        asset,
                        label["label"],
                        source=label.get("source", "manual"),
                        confidence=float(label.get("confidence", 1.0)),
                        asserted_by="cpctl seed",
                    )
            for entry in document.get("principals", []):
                await service.upsert_principal(
                    entry["external_id"],
                    type_=entry.get("type"),
                    display_name=entry.get("display_name"),
                    description=entry.get("description"),
                    attributes=entry.get("attributes"),
                )
            console.print(
                f"catalog: [green]{len(document.get('assets', []))} assets[/], "
                f"[green]{len(document.get('principals', []))} principals[/]"
            )
            await AuditService(session).append(
                AuditEvent.CONFIG_CHANGED,
                actor="cpctl seed",
                subject="reference-set",
                payload={"policies": str(policies), "catalog": str(catalog)},
            )

    run(inner())


# --------------------------------------------------------------------------- #
# policy
# --------------------------------------------------------------------------- #


@policy_app.command("list")
def policy_list(
    enabled: Annotated[bool | None, typer.Option(help="Filter by enabled state.")] = None,
) -> None:
    """List stored policies, highest priority first."""

    async def inner() -> None:
        async with session_scope() as session:
            records = await PolicyStore(session).list_records(enabled=enabled, limit=1000)
            table = Table("priority", "effect", "key", "name", "v", "on")
            for record in records:
                table.add_row(
                    str(record.priority),
                    f"[{EFFECT_STYLE.get(record.effect, 'white')}]{record.effect}[/]",
                    record.key,
                    record.name,
                    str(record.version),
                    "[green]yes[/]" if record.enabled else "[dim]no[/]",
                )
            console.print(table)

    run(inner())


@policy_app.command("show")
def policy_show(key: str) -> None:
    """Print one policy document."""

    async def inner() -> None:
        async with session_scope() as session:
            record = await PolicyStore(session).get_record(key)
            if record is None:
                fail(f"no policy {key!r}")
            console.print(
                Syntax(
                    yaml.safe_dump(record.document, sort_keys=False),
                    "yaml",
                    theme="ansi_dark",
                )
            )

    run(inner())


@policy_app.command("validate")
def policy_validate(path: Path) -> None:
    """Check a policy file without touching the database.

    The right thing to run in CI on a pull request that edits policy.
    """
    document = load_document(path)
    entries = document.get("policies", document) if isinstance(document, dict) else document
    if isinstance(entries, dict):
        entries = [entries]

    failures = 0
    for entry in entries:
        try:
            policy = Policy.model_validate(entry)
        except Exception as exc:
            failures += 1
            console.print(f"[red]invalid[/] {entry.get('key', '<no key>')}: {exc}")
        else:
            console.print(
                f"[green]ok[/]      {policy.key} "
                f"[dim]({policy.effect}, priority {policy.priority})[/]"
            )
    if failures:
        fail(f"{failures} of {len(entries)} policies are invalid")
    console.print(f"[green]all {len(entries)} policies are valid[/]")


@policy_app.command("sync")
def policy_sync(
    path: Path,
    prune: Annotated[bool, typer.Option(help="Delete policies absent from the file.")] = False,
) -> None:
    """Reconcile the stored policy set with a file."""

    async def inner() -> None:
        document = load_document(path)
        policy_set = PolicySet.model_validate(document)
        async with session_scope() as session:
            result = await PolicyStore(session).sync(
                policy_set.policies, actor="cpctl", prune=prune
            )
            for label, keys in result.items():
                if keys:
                    console.print(f"{label}: {', '.join(keys)}")

    run(inner())


# --------------------------------------------------------------------------- #
# decide / classify
# --------------------------------------------------------------------------- #


@app.command("decide")
def decide(
    principal: Annotated[str, typer.Option(help="Principal id, e.g. agent:support_bot.")],
    action: Annotated[str, typer.Option(help="read, embed, infer, export, ...")],
    resource: Annotated[str, typer.Option(help="Resource URN.")] = "",
    principal_type: Annotated[str, typer.Option()] = "agent",
    payload: Annotated[str, typer.Option(help="Content to classify and govern.")] = "",
    destination: Annotated[str, typer.Option()] = "internal",
    purpose: Annotated[str, typer.Option()] = "",
    explain: Annotated[bool, typer.Option(help="Show the full evaluation trace.")] = False,
) -> None:
    """Ask the policy engine a question from the command line."""

    async def inner() -> None:
        context: dict[str, Any] = {"destination": destination}
        if purpose:
            context["purpose"] = purpose
        request = DecideRequest.model_validate(
            {
                "principal": {"id": principal, "type": principal_type},
                "action": action,
                "resource": {"urn": resource or None},
                "context": context,
                "payload": payload or None,
                "options": {"explain": explain, "persist": True},
            }
        )
        async with session_scope() as session:
            response = await PolicyDecisionPoint(session).decide(request, actor="cpctl")

        style = EFFECT_STYLE.get(response.effect, "white")
        console.print(
            Panel(
                f"[bold {style}]{response.effect.upper()}[/]\n\n{response.reason}",
                title=f"{principal} -> {action} -> {resource or '(no resource)'}",
                border_style=style,
            )
        )
        if response.classifications:
            console.print(f"[dim]labels:[/] {', '.join(response.classifications)}")
        if response.regulations:
            console.print(f"[dim]regulations:[/] {', '.join(response.regulations)}")
        for obligation in response.obligations:
            console.print(f"[dim]obligation:[/] {json.dumps(obligation)}")
        if response.redactions:
            console.print(f"[dim]redactions:[/] {len(response.redactions)}")
        if response.payload is not None:
            console.print(Panel(str(response.payload), title="governed payload"))
        if explain and response.explain:
            table = Table("policy", "effect", "matched", "why")
            for entry in response.explain["trace"]:
                table.add_row(
                    entry["key"],
                    entry["effect"],
                    "[green]yes[/]" if entry["matched"] else "[dim]no[/]",
                    entry["reason"][:80],
                )
            console.print(table)
        console.print(f"[dim]{response.latency_ms} ms[/]")

    run(inner())


@app.command("classify")
def classify(
    text: Annotated[str, typer.Argument(help="Text to scan, or '-' to read stdin.")],
) -> None:
    """Run the detectors over some text and report what is in it."""
    body = sys.stdin.read() if text == "-" else text
    try:
        parsed = json.loads(body)
        result = scan_structured(parsed)
    except (json.JSONDecodeError, TypeError):
        result = scan_text(body)

    if not result.findings:
        console.print("[green]no sensitive data detected[/]")
        return
    table = Table("label", "severity", "confidence", "where", "preview")
    for finding in result.findings:
        table.add_row(
            finding.label,
            str(finding.severity),
            f"{finding.confidence:.2f}",
            finding.path or f"{finding.start}:{finding.end}",
            finding.preview,
        )
    console.print(table)
    summary = result.summary()
    if summary["regulations"]:
        console.print(f"[dim]implicates:[/] {', '.join(summary['regulations'])}")


# --------------------------------------------------------------------------- #
# catalog
# --------------------------------------------------------------------------- #


def _registry() -> SourceRegistry:
    try:
        return SourceRegistry.from_file(get_settings().sources_file)
    except SourceConfigError as exc:
        fail(str(exc))


@catalog_app.command("sources")
def catalog_sources() -> None:
    """List the configured systems the catalog can discover from."""
    registry = _registry()
    if not len(registry):
        console.print(
            f"[dim]no sources configured in "
            f"{get_settings().sources_file}[/]\n"
            "See seed/sources.example.yaml for the format."
        )
        return
    table = Table("name", "adapter", "target", "scan", "on", "description")
    for config in registry.all():
        table.add_row(
            config.name,
            config.adapter,
            # escape(): a target reads "[configured]", and Rich would otherwise
            # parse the brackets as a style tag and render nothing at all.
            escape(config.target),
            "[green]yes[/]" if config.scan else "[dim]no[/]",
            "[green]yes[/]" if config.enabled else "[dim]no[/]",
            config.description,
        )
    console.print(table)


@catalog_app.command("discover")
def catalog_discover(
    source: Annotated[
        str | None, typer.Argument(help="A configured source name. Omit to use --adapter.")
    ] = None,
    adapter: Annotated[
        str | None, typer.Option(help="Discover ad hoc: postgres or qdrant.")
    ] = None,
    dsn: Annotated[str | None, typer.Option(help="postgres DSN, with --adapter.")] = None,
    base_url: Annotated[str | None, typer.Option(help="qdrant URL, with --adapter.")] = None,
    scan: Annotated[
        bool, typer.Option(help="Sample each asset and classify what is in it.")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would change. Reads nothing.")
    ] = False,
    include: Annotated[list[str] | None, typer.Option(help="URN glob to keep.")] = None,
    exclude: Annotated[list[str] | None, typer.Option(help="URN glob to skip.")] = None,
    owner: Annotated[str, typer.Option(help="Owner to record on every asset.")] = "",
    max_assets: Annotated[int, typer.Option(help="Stop after this many.")] = 0,
    sample_limit: Annotated[int, typer.Option(help="Records to read per asset.")] = 0,
    min_confidence: Annotated[float, typer.Option(help="Floor for scan findings.")] = 0.0,
) -> None:
    """Enumerate a system and fold what it finds into the catalog.

    Start with --dry-run against an unfamiliar database. Add --scan only once
    you know what it will read: sampling reads real records, and --exclude is
    how you keep it away from an audit table or anything under legal hold.
    """
    if source and adapter:
        fail("give a configured source name or --adapter, not both")

    if source:
        try:
            config = _registry().get(source)
        except UnknownSource as exc:
            fail(str(exc))
        if not config.enabled:
            fail(f"source {source!r} is disabled")
    elif adapter:
        try:
            config = SourceConfig(name="ad-hoc", adapter=adapter, dsn=dsn, base_url=base_url)
        except Exception as exc:
            fail(str(exc))
        if not config.configured:
            fail(f"--adapter {adapter} needs {'--dsn' if adapter == 'postgres' else '--base-url'}")
    else:
        fail("name a configured source, or pass --adapter with its connection details")

    # Explicit flags win over the source's own defaults; zero means "not given".
    effective_scan = scan or config.scan
    effective_include = list(include or config.include)
    effective_exclude = list(exclude or config.exclude)
    effective_owner = owner or config.owner
    effective_max = max_assets or config.max_assets
    effective_sample = sample_limit or config.sample_limit
    effective_confidence = min_confidence or config.min_confidence

    async def inner() -> None:
        built = config.build()
        try:
            async with session_scope() as session:
                report = await DiscoveryService(session=session).run(
                    built,
                    source=config.name,
                    scan=effective_scan,
                    dry_run=dry_run,
                    max_assets=effective_max,
                    sample_limit=effective_sample,
                    min_confidence=effective_confidence,
                    include=effective_include,
                    exclude=effective_exclude,
                    owner=effective_owner,
                    actor="cpctl",
                )
        finally:
            # Adapters that own a connection pool have to release it, whatever
            # happened during the run.
            closer = getattr(built, "aclose", None)
            if closer is not None:
                await closer()
        _print_report(report)

    run(inner())


def _print_report(report: Any) -> None:
    """Render a discovery report, leading with anything that needs attention."""
    if report.errors:
        for message in report.errors:
            error_console.print(f"[bold red]{message}[/]")
        raise typer.Exit(code=1)

    heading = "would register" if report.dry_run else "registered"
    console.print(
        f"[bold]{report.source}[/] via {report.adapter}: "
        f"{report.discovered} asset(s) discovered, "
        f"[green]{len(report.created)} new[/], {len(report.updated)} existing"
        + (f", [red]{len(report.failed)} failed[/]" if report.failed else "")
    )
    if report.truncated:
        console.print("[yellow]capped by --max-assets; some assets were not examined[/]")

    if report.classified:
        table = Table("urn", "kind", heading, "labels", "sampled")
        for outcome in report.classified:
            table.add_row(
                outcome.urn,
                outcome.kind,
                "[green]new[/]" if outcome.created else "[dim]existing[/]",
                ", ".join(outcome.labels),
                f"{outcome.records_sampled}" + (" (partial)" if outcome.partial_sample else ""),
            )
        console.print(table)

    if report.label_counts:
        console.print(
            "[dim]labels:[/] " + ", ".join(f"{k} x{v}" for k, v in report.label_counts.items())
        )
    if report.regulations:
        console.print(f"[dim]implicates:[/] {', '.join(report.regulations)}")

    for outcome in report.failed:
        error_console.print(f"[red]{outcome.urn}[/]: {outcome.error}")

    if report.dry_run:
        console.print("[yellow]dry run -- nothing was written and nothing was read[/]")


# --------------------------------------------------------------------------- #
# key
# --------------------------------------------------------------------------- #


@key_app.command("issue")
def key_issue(
    name: Annotated[str, typer.Option(help="Human label for this key.")],
    scope: Annotated[
        list[str] | None, typer.Option(help="Repeatable. See --help for names.")
    ] = None,
    principal: Annotated[
        list[str] | None,
        typer.Option(help="Restrict to these principal ids. Supports a trailing *."),
    ] = None,
) -> None:
    """Issue an API key. The secret is printed once and never stored."""

    async def inner() -> None:
        try:
            scopes = normalise_scopes(scope or [Scope.DECIDE, Scope.CATALOG_READ])
        except ValueError as exc:
            fail(str(exc))
        async with session_scope() as session:
            record, issued = await ApiKeyService(session).issue(
                name=name,
                scopes=scopes,
                allowed_principals=principal or [],
                created_by="cpctl",
            )
            await AuditService(session).append(
                AuditEvent.KEY_ISSUED,
                actor="cpctl",
                subject=record.prefix,
                payload={"name": name, "scopes": scopes},
            )
        console.print(
            Panel(
                f"[bold]{issued.plaintext}[/]\n\n"
                f"[dim]scopes:[/] {', '.join(scopes)}\n"
                f"[dim]principals:[/] {', '.join(principal or ['(any)'])}",
                title=f"key issued: {name}",
                subtitle="[red]store this now -- it cannot be retrieved again[/]",
                border_style="yellow",
            )
        )

    run(inner())


@key_app.command("list")
def key_list(
    include_revoked: Annotated[bool, typer.Option()] = False,
) -> None:
    """List keys. Secrets are never shown."""

    async def inner() -> None:
        async with session_scope() as session:
            records = await ApiKeyService(session).list_keys(include_revoked=include_revoked)
            table = Table("prefix", "name", "scopes", "last used", "state")
            for record in records:
                table.add_row(
                    record.prefix,
                    record.name,
                    ", ".join(record.scopes or []),
                    record.last_used_at.isoformat(timespec="seconds")
                    if record.last_used_at
                    else "[dim]never[/]",
                    "[red]revoked[/]" if record.revoked_at else "[green]active[/]",
                )
            console.print(table)

    run(inner())


@key_app.command("revoke")
def key_revoke(prefix: str) -> None:
    """Revoke a key by its prefix."""

    async def inner() -> None:
        async with session_scope() as session:
            record = await ApiKeyService(session).revoke(prefix)
            if record is None:
                fail(f"no active key with prefix {prefix!r}")
            await AuditService(session).append(
                AuditEvent.KEY_REVOKED, actor="cpctl", subject=prefix, payload={}
            )
        console.print(f"[green]revoked[/] {prefix}")

    run(inner())


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #


@audit_app.command("verify")
def audit_verify(
    start: Annotated[int, typer.Option(help="First sequence number to check.")] = 1,
    end: Annotated[int | None, typer.Option(help="Last sequence number to check.")] = None,
) -> None:
    """Recompute the hash chain and report any tampering."""

    async def inner() -> None:
        async with session_scope() as session:
            result = await AuditService(session).verify(start_seq=start, end_seq=end)
        if result.valid:
            console.print(
                Panel(
                    f"[green]{result.message}[/]",
                    title="audit chain",
                    border_style="green",
                )
            )
            return
        body = [f"[red]{result.message}[/]"]
        if result.corrupted:
            body.append(f"records with an altered digest: {list(result.corrupted)}")
        if result.broken_links:
            body.append(f"records whose predecessor link is wrong: {list(result.broken_links)}")
        if result.sequence_errors:
            body.append(f"gaps or repeats at: {list(result.sequence_errors)}")
        console.print(Panel("\n".join(body), title="audit chain", border_style="red"))
        raise typer.Exit(code=2)

    run(inner())


@audit_app.command("tail")
def audit_tail(
    limit: Annotated[int, typer.Option()] = 20,
    event: Annotated[str | None, typer.Option(help="Filter by event type.")] = None,
) -> None:
    """Show the most recent audit records."""

    async def inner() -> None:
        async with session_scope() as session:
            rows = await AuditService(session).list_records(limit=limit, event=event)
            table = Table("seq", "when", "event", "actor", "subject")
            for row in reversed(rows):
                table.add_row(
                    str(row.seq),
                    row.timestamp.isoformat(timespec="seconds"),
                    row.event,
                    row.actor,
                    row.subject[:48],
                )
            console.print(table)

    run(inner())


# --------------------------------------------------------------------------- #
# serve
# --------------------------------------------------------------------------- #


@app.command("serve")
def serve(
    host: Annotated[str, typer.Option()] = "0.0.0.0",  # noqa: S104
    port: Annotated[int, typer.Option()] = 8000,
    reload: Annotated[bool, typer.Option(help="Reload on source changes.")] = False,
    workers: Annotated[
        int,
        typer.Option(
            help="Worker processes. Classification is CPU-bound and only partly "
            "releases the GIL, so this is what raises throughput; threads do not."
        ),
    ] = 1,
) -> None:
    """Run the API server."""
    import uvicorn

    if reload and workers > 1:
        fail("--reload and --workers are mutually exclusive")
    uvicorn.run(
        "control_plane.main:app",
        host=host,
        port=port,
        reload=reload,
        workers=None if reload else workers,
        log_config=None,
    )


@app.command("version")
def version() -> None:
    """Print the version and effective configuration."""
    settings = get_settings()
    console.print(
        Panel(
            f"[bold]{settings.app_name}[/] 0.1.0\n"
            f"[dim]environment:[/]   {settings.environment}\n"
            f"[dim]database:[/]      {_safe_dsn(settings.database_url)}\n"
            f"[dim]default effect:[/] {settings.default_effect}\n"
            f"[dim]fail closed:[/]   {settings.fail_closed}\n"
            f"[dim]auth:[/]          {'DISABLED' if settings.auth_disabled else 'enabled'}",
            title="cpctl",
        )
    )


def _safe_dsn(url: str) -> str:
    """Strip the password before a DSN reaches a terminal or a log."""
    if "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    credentials, _, host = rest.rpartition("@")
    user, _, _password = credentials.partition(":")
    return f"{scheme}://{user}:***@{host}"


if __name__ == "__main__":
    app()
