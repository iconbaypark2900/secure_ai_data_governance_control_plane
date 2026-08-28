"""Reversing tokenisation.

This is the most sensitive endpoint the control plane exposes. Everything else
either withholds sensitive data or describes it; this hands it back.

Three things follow from that:

*It has its own scope.* ``detokenize`` is not bundled into ``catalog:read`` or
``audit:read``, so an investigator can be given re-identification without being
given the ability to read the catalog, and vice versa.

*Every call is audited, including the failures.* A request that recovers nothing
is still someone attempting re-identification, and that is exactly what an
investigation into a misuse of this endpoint would need to see.

*The audit record never contains what was recovered.* Logging the plaintext would
turn the tamper-evident log into the store of sensitive values that the
tokenisation design exists to avoid.

One thing this module cannot enforce, and which matters as much as anything it
can: the recovered values travel in the **response body**. A reverse proxy, load
balancer, or APM agent in front of the control plane that records response
bodies would accumulate exactly the store this whole design avoids -- quietly,
in a component nobody thinks of as holding data. Responses here are marked
``Cache-Control: no-store`` and ``X-Content-Sensitive``, which stops the caching
half; the logging half is a deployment decision and is called out in the README.

``/verify`` is the operation to reach for first. It answers "is this token this
value?" without disclosing anything, which is the real question most of the time.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from control_plane.api.deps import AuditDep, CallerDep, SettingsDep, require_scope
from control_plane.audit.chain import AuditEvent, content_digest
from control_plane.auth.keys import Scope
from control_plane.redaction.tokenization import DeterministicTokenizer

router = APIRouter(prefix="/detokenize", tags=["tokens"])

#: An investigator holds a row of tokens, not a table of them. A large batch is
#: a bulk re-identification, which is a different act needing a different review.
MAX_TOKENS = 50


class DetokenizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tokens: Annotated[list[str], Field(min_length=1, max_length=MAX_TOKENS)]
    justification: str = Field(
        min_length=3,
        max_length=500,
        description="Why this re-identification is warranted -- an incident or "
        "ticket reference. Required, and recorded in the audit chain against "
        "your name.",
    )


class DetokenizeResult(BaseModel):
    token: str
    recovered: bool
    value: str | None = None


class DetokenizeResponse(BaseModel):
    results: list[DetokenizeResult]
    recovered: int
    requested: int


class VerifyRequest(BaseModel):
    """Confirm a suspected match without disclosing anything."""

    model_config = ConfigDict(extra="forbid")

    token: str
    label: str = Field(description="The label the token was minted under.")
    value: str = Field(description="The value you believe it stands for.")
    justification: str = Field(min_length=3, max_length=500)


class VerifyResponse(BaseModel):
    matches: bool


def _mark_sensitive(response: Response) -> None:
    """Tell everything downstream not to retain this body.

    Not a guarantee -- a proxy configured to log bodies will log them anyway --
    but it removes the accidental cases, and it makes the intent legible to
    whoever configures that proxy.
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Sensitive"] = "re-identified-values"


def _tokenizer(settings: SettingsDep) -> Any:
    tokenizer = DeterministicTokenizer.from_settings(settings)
    if tokenizer is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "tokenisation is not configured on this deployment, so there is "
                "nothing to reverse; set CP_TOKENIZATION_KEY"
            ),
        )
    return tokenizer


@router.post(
    "",
    response_model=DetokenizeResponse,
    summary="Reverse tokens to the values they replaced",
    dependencies=[Depends(require_scope(Scope.DETOKENIZE))],
)
async def detokenize(
    body: DetokenizeRequest,
    settings: SettingsDep,
    audit: AuditDep,
    caller: CallerDep,
    response: Response,
) -> DetokenizeResponse:
    """Recover the original values.

    A token that cannot be read -- malformed, minted under a key this deployment
    no longer holds, or tampered with -- comes back as ``recovered: false``
    without saying which. The caller of a re-identification API should not be
    able to use it as an oracle for distinguishing those cases.
    """
    _mark_sensitive(response)
    tokenizer = _tokenizer(settings)
    results = [
        DetokenizeResult(
            token=token, recovered=(value := tokenizer.detokenize(token)) is not None, value=value
        )
        for token in body.tokens
    ]
    recovered = sum(1 for result in results if result.recovered)

    await audit.append(
        AuditEvent.TOKENS_REVERSED,
        actor=caller.identity,
        subject="detokenize",
        payload={
            "requested": len(body.tokens),
            "recovered": recovered,
            "justification": body.justification,
            # Digests, not tokens and certainly not values: enough to tie this
            # call to a specific set of tokens during an investigation, and not
            # enough for the log to become a copy of what was recovered.
            "token_digests": [
                content_digest(token, settings.audit_key_bytes())[:16] for token in body.tokens
            ],
        },
    )
    return DetokenizeResponse(results=results, recovered=recovered, requested=len(body.tokens))


@router.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Check whether a token stands for a value, without revealing it",
    dependencies=[Depends(require_scope(Scope.DETOKENIZE))],
)
async def verify(
    body: VerifyRequest,
    settings: SettingsDep,
    audit: AuditDep,
    caller: CallerDep,
) -> VerifyResponse:
    """Confirm or refute a suspected match.

    Prefer this over reversing. "Is the account in this incident the same one in
    that report?" is answerable here without anyone receiving a plaintext they
    did not already hold.
    """
    tokenizer = _tokenizer(settings)
    matches = tokenizer.verify(body.label, body.value, body.token)
    await audit.append(
        AuditEvent.TOKENS_VERIFIED,
        actor=caller.identity,
        subject=body.label,
        payload={
            "matched": matches,
            "justification": body.justification,
            "token_digest": content_digest(body.token, settings.audit_key_bytes())[:16],
            # The candidate is digested too. The caller already knows it; the
            # log has no reason to.
            "value_digest": content_digest(body.value, settings.audit_key_bytes())[:16],
        },
    )
    return VerifyResponse(matches=matches)
