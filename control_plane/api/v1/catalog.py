"""Catalog administration: assets, their labels, and principals.

URNs contain ``://`` and cannot travel safely in a path segment, so assets are
addressed by a ``urn`` query parameter throughout.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from control_plane.api.deps import AuditDep, CallerDep, CatalogDep, require_scope
from control_plane.audit.chain import AuditEvent
from control_plane.auth.keys import Scope
from control_plane.classification import taxonomy
from control_plane.classification.scanner import Scanner
from control_plane.models.catalog import DataAsset, Principal
from control_plane.schemas.catalog import (
    AssetIn,
    AssetOut,
    ClassificationIn,
    ClassificationOut,
    PrincipalIn,
    PrincipalOut,
    ScanRequest,
    ScanResponse,
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
