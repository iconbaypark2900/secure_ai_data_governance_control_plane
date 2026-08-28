"""Catalog administration: assets, their labels, and principals.

URNs contain ``://`` and cannot travel safely in a path segment, so assets are
addressed by a ``urn`` query parameter throughout.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from control_plane.adapters.registry import SourceConfigError, SourceRegistry, UnknownSource
from control_plane.api.deps import (
    AuditDep,
    CallerDep,
    CatalogDep,
    SessionDep,
    SettingsDep,
    require_scope,
)
from control_plane.audit.chain import AuditEvent
from control_plane.auth.keys import Scope
from control_plane.catalog.discovery import DiscoveryService
from control_plane.classification import taxonomy
from control_plane.classification.scanner import Scanner
from control_plane.models.catalog import DataAsset, Principal
from control_plane.schemas.catalog import (
    AssetIn,
    AssetOut,
    ClassificationIn,
    ClassificationOut,
    DiscoverRequest,
    DiscoveryReportOut,
    PrincipalIn,
    PrincipalOut,
    ScanRequest,
    ScanResponse,
    SourceOut,
)

router = APIRouter(tags=["catalog"])


async def _asset_out(catalog: Any, asset: DataAsset) -> AssetOut:
    records = await catalog.classifications_for(asset.id)
    labels = sorted({record.label for record in records})
    return AssetOut(
        urn=asset.urn,
        name=asset.name,
        kind=asset.kind,
        owner=asset.owner,
        description=asset.description,
        attributes=dict(asset.attributes or {}),
        classifications=[
            ClassificationOut(
                label=record.label,
                source=record.source,
                confidence=record.confidence,
                asserted_by=record.asserted_by,
                evidence=dict(record.evidence or {}),
            )
            for record in records
        ],
        labels=labels,
        regulations=list(taxonomy.regulations_for(labels)),
        last_scanned_at=asset.last_scanned_at.isoformat() if asset.last_scanned_at else None,
        created_at=asset.created_at.isoformat() if asset.created_at else None,
        updated_at=asset.updated_at.isoformat() if asset.updated_at else None,
    )


def _principal_out(principal: Principal) -> PrincipalOut:
    return PrincipalOut(
        external_id=principal.external_id,
        type=principal.type,
        display_name=principal.display_name,
        description=principal.description,
        attributes=dict(principal.attributes or {}),
        enabled=principal.enabled,
        created_at=principal.created_at.isoformat() if principal.created_at else None,
    )


# --- assets ----------------------------------------------------------------- #


@router.get(
    "/assets",
    response_model=list[AssetOut],
    summary="List data assets",
    dependencies=[Depends(require_scope(Scope.CATALOG_READ))],
)
async def list_assets(
    catalog: CatalogDep,
    kind: Annotated[str | None, Query()] = None,
    owner: Annotated[str | None, Query()] = None,
    label: Annotated[str | None, Query(description="Filter by label, e.g. 'phi'")] = None,
    search: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AssetOut]:
    assets = await catalog.list_assets(
        kind=kind, owner=owner, label=label, search=search, limit=limit, offset=offset
    )
    return [await _asset_out(catalog, asset) for asset in assets]


@router.post(
    "/assets",
    response_model=AssetOut,
    summary="Register or update a data asset",
    dependencies=[Depends(require_scope(Scope.CATALOG_WRITE))],
)
async def upsert_asset(
    body: AssetIn, catalog: CatalogDep, audit: AuditDep, caller: CallerDep
) -> AssetOut:
    asset, created = await catalog.upsert_asset(
        body.urn,
        name=body.name,
        kind=body.kind,
        owner=body.owner,
        description=body.description,
        attributes=body.attributes,
    )
    await audit.append(
        AuditEvent.ASSET_REGISTERED if created else AuditEvent.ASSET_UPDATED,
        actor=caller.identity,
        subject=asset.urn,
        payload={"kind": asset.kind, "owner": asset.owner},
    )
    return await _asset_out(catalog, asset)


@router.get(
    "/assets/resolve",
    summary="Resolve a URN to its effective labels, including inherited ones",
    dependencies=[Depends(require_scope(Scope.CATALOG_READ))],
)
async def resolve_asset(urn: Annotated[str, Query()], catalog: CatalogDep) -> dict[str, Any]:
    """What the policy engine would see for this URN.

    Answers "why is this table treated as PHI?" -- the ``matched_patterns`` field
    names the pattern registration responsible.
    """
    return (await catalog.resolve(urn)).to_dict()


@router.get(
    "/assets/detail",
    response_model=AssetOut,
    summary="Retrieve one asset",
    dependencies=[Depends(require_scope(Scope.CATALOG_READ))],
)
async def get_asset(urn: Annotated[str, Query()], catalog: CatalogDep) -> AssetOut:
    asset = await catalog.get_asset(urn)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"no asset {urn!r}")
    return await _asset_out(catalog, asset)


@router.delete(
    "/assets",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an asset and its labels",
    dependencies=[Depends(require_scope(Scope.CATALOG_WRITE))],
)
async def delete_asset(
    urn: Annotated[str, Query()], catalog: CatalogDep, audit: AuditDep, caller: CallerDep
) -> None:
    if not await catalog.delete_asset(urn):
        raise HTTPException(status_code=404, detail=f"no asset {urn!r}")
    await audit.append(AuditEvent.ASSET_DELETED, actor=caller.identity, subject=urn, payload={})


@router.post(
    "/assets/classifications",
    response_model=AssetOut,
    summary="Attach a sensitivity label to an asset",
    dependencies=[Depends(require_scope(Scope.CATALOG_WRITE))],
)
async def add_classification(
    urn: Annotated[str, Query()],
    body: ClassificationIn,
    catalog: CatalogDep,
    audit: AuditDep,
    caller: CallerDep,
) -> AssetOut:
    asset = await catalog.get_asset(urn)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"no asset {urn!r}")
    await catalog.set_classification(
        asset,
        body.label,
        source=body.source,
        confidence=body.confidence,
        evidence=body.evidence,
        asserted_by=body.asserted_by or caller.identity,
    )
    await audit.append(
        AuditEvent.ASSET_CLASSIFIED,
        actor=caller.identity,
        subject=urn,
        payload={"label": body.label, "source": body.source, "confidence": body.confidence},
    )
    return await _asset_out(catalog, asset)


@router.delete(
    "/assets/classifications",
    response_model=AssetOut,
    summary="Detach a sensitivity label",
    dependencies=[Depends(require_scope(Scope.CATALOG_WRITE))],
)
async def remove_classification(
    urn: Annotated[str, Query()],
    label: Annotated[str, Query()],
    catalog: CatalogDep,
    audit: AuditDep,
    caller: CallerDep,
    source: Annotated[str | None, Query()] = None,
) -> AssetOut:
    asset = await catalog.get_asset(urn)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"no asset {urn!r}")
    removed = await catalog.remove_classification(asset, label, source=source)
    if not removed:
        raise HTTPException(status_code=404, detail=f"asset {urn!r} does not carry {label!r}")
    await audit.append(
        AuditEvent.ASSET_CLASSIFIED,
        actor=caller.identity,
        subject=urn,
        payload={"label": label, "removed": removed, "source": source},
    )
    return await _asset_out(catalog, asset)


@router.post(
    "/assets/scan",
    response_model=ScanResponse,
    summary="Classify a sample and record what it implies about the asset",
    dependencies=[Depends(require_scope(Scope.CATALOG_WRITE))],
)
async def scan_asset(
    body: ScanRequest, catalog: CatalogDep, audit: AuditDep, caller: CallerDep
) -> ScanResponse:
    """Profile an asset from a representative sample.

    Only masked previews and counts are stored as evidence -- enough to justify
    a label, not enough to reconstruct the data.
    """
    asset = await catalog.get_asset(body.urn)
    if asset is None:
        asset, _ = await catalog.upsert_asset(body.urn)

    scanner = Scanner(min_confidence=body.min_confidence)
    result = (
        scanner.scan_text(body.sample)
        if isinstance(body.sample, str)
        else scanner.scan_structured(body.sample)
    )

    applied: list[str] = []
    if body.persist:
        records = await catalog.apply_scan(
            asset, result, asserted_by=body.asserted_by, min_confidence=body.min_confidence
        )
        applied = sorted({record.label for record in records})
        await audit.append(
            AuditEvent.SCAN_COMPLETED,
            actor=caller.identity,
            subject=body.urn,
            payload={
                "labels": applied,
                "finding_count": len(result.findings),
                "scanned_chars": result.scanned_chars,
            },
        )

    summary = result.summary()
    return ScanResponse(
        urn=body.urn,
        labels_applied=applied,
        label_counts=summary["label_counts"],
        max_severity=summary["max_severity"],
        regulations=summary["regulations"],
        finding_count=summary["finding_count"],
        scanned_chars=summary["scanned_chars"],
        truncated=summary["truncated"],
        persisted=body.persist,
    )


# --- discovery -------------------------------------------------------------- #


def _load_registry(settings: SettingsDep) -> SourceRegistry:
    """Read the sources file per request, so an edit takes effect on save.

    Discovery is not a hot path and the file is small, so there is nothing to
    gain from caching it and something to lose: a stale registry that needs a
    restart to pick up a source someone just added.
    """
    try:
        return SourceRegistry.from_file(settings.sources_file)
    except SourceConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/catalog/sources",
    response_model=list[SourceOut],
    summary="List the systems the catalog can discover from",
    dependencies=[Depends(require_scope(Scope.CATALOG_READ))],
)
async def list_sources(settings: SettingsDep) -> list[SourceOut]:
    """Configured sources, with credentials redacted.

    Credentials are configured server-side and referred to by name, so they never
    travel in an API request body.
    """
    return [
        SourceOut(
            name=config.name,
            adapter=config.adapter,
            description=config.description,
            enabled=config.enabled,
            target=config.target,
            owner=config.owner,
            include=list(config.include),
            exclude=list(config.exclude),
            scan=config.scan,
            max_assets=config.max_assets,
            sample_limit=config.sample_limit,
            min_confidence=config.min_confidence,
        )
        for config in _load_registry(settings).all()
    ]


@router.post(
    "/catalog/sources/{name}/discover",
    response_model=DiscoveryReportOut,
    summary="Enumerate a source and fold what it finds into the catalog",
    dependencies=[Depends(require_scope(Scope.CATALOG_WRITE))],
)
async def discover_source(
    name: str,
    body: DiscoverRequest,
    session: SessionDep,
    settings: SettingsDep,
    caller: CallerDep,
) -> DiscoveryReportOut:
    """Run discovery against a configured source.

    Synchronous, and bounded by ``max_assets``. A run over a large warehouse
    should go through `cpctl catalog discover`, which is not sitting behind an
    HTTP timeout.

    Requires catalog:write even for a dry run: it opens a connection to a
    production system using stored credentials, which is an operator action
    whether or not it writes anything.
    """
    registry = _load_registry(settings)
    try:
        config = registry.get(name)
    except UnknownSource as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not config.enabled:
        raise HTTPException(status_code=409, detail=f"source {name!r} is disabled")
    try:
        adapter = config.build()
    except SourceConfigError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    try:
        report = await DiscoveryService(session=session).run(
            adapter,
            source=config.name,
            scan=config.scan if body.scan is None else body.scan,
            dry_run=body.dry_run,
            max_assets=body.max_assets or config.max_assets,
            sample_limit=body.sample_limit or config.sample_limit,
            min_confidence=(
                config.min_confidence if body.min_confidence is None else body.min_confidence
            ),
            include=list(config.include if body.include is None else body.include),
            exclude=list(config.exclude if body.exclude is None else body.exclude),
            owner=config.owner if body.owner is None else body.owner,
            actor=caller.identity,
        )
    finally:
        closer = getattr(adapter, "aclose", None)
        if closer is not None:
            await closer()

    return DiscoveryReportOut.model_validate(report.to_dict())


# --- principals ------------------------------------------------------------- #


@router.get(
    "/principals",
    response_model=list[PrincipalOut],
    summary="List principals",
    dependencies=[Depends(require_scope(Scope.CATALOG_READ))],
)
async def list_principals(
    catalog: CatalogDep,
    type: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[PrincipalOut]:
    principals = await catalog.list_principals(type_=type, limit=limit, offset=offset)
    return [_principal_out(principal) for principal in principals]


@router.post(
    "/principals",
    response_model=PrincipalOut,
    summary="Register or update a principal",
    dependencies=[Depends(require_scope(Scope.CATALOG_WRITE))],
)
async def upsert_principal(
    body: PrincipalIn, catalog: CatalogDep, audit: AuditDep, caller: CallerDep
) -> PrincipalOut:
    """Register an identity and the attributes policies may match on.

    Attributes set here are authoritative: they override anything a caller
    asserts about itself at decision time.
    """
    principal, created = await catalog.upsert_principal(
        body.external_id,
        type_=body.type,
        display_name=body.display_name,
        description=body.description,
        attributes=body.attributes,
    )
    await audit.append(
        AuditEvent.PRINCIPAL_CREATED if created else AuditEvent.PRINCIPAL_UPDATED,
        actor=caller.identity,
        subject=principal.external_id,
        payload={"type": principal.type, "attributes": dict(principal.attributes or {})},
    )
    return _principal_out(principal)


@router.get(
    "/principals/detail",
    response_model=PrincipalOut,
    summary="Retrieve one principal",
    dependencies=[Depends(require_scope(Scope.CATALOG_READ))],
)
async def get_principal(external_id: Annotated[str, Query()], catalog: CatalogDep) -> PrincipalOut:
    principal = await catalog.get_principal(external_id)
    if principal is None:
        raise HTTPException(status_code=404, detail=f"no principal {external_id!r}")
    return _principal_out(principal)
