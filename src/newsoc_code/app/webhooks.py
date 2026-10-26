"""``POST /webhooks/github``: verify, record, enqueue, answer fast.

GitHub gives up on a delivery after 10 seconds, so this handler never scans anything. It checks
the signature, stores the delivery id (the primary key makes redeliveries idempotent), queues
work in the same transaction, and returns.

If processing fails, the transaction rolls back, the delivery is not recorded, the response is
a 500, and a redelivery from GitHub is processed normally.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy.dialects.postgresql import insert as pg_insert
from starlette.concurrency import run_in_threadpool

from newsoc_code.app.intake import apply_actions
from newsoc_code.db.models import WebhookDelivery, utcnow
from newsoc_code.db.session import session_scope
from newsoc_code.github.events import parse_event
from newsoc_code.github.signature import verify_signature
from newsoc_code.report.render import CHECK_NAME

log = logging.getLogger("newsoc.webhook")
router = APIRouter()
MAX_BODY_BYTES = 2_000_000  # real pull_request payloads are tens of kilobytes


def _reply(code: int, /, **body: Any) -> JSONResponse:
    return JSONResponse(body, status_code=code)


async def _read_limited(request: Request) -> bytes | None:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return None
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/webhooks/github")
async def github_webhook(request: Request) -> JSONResponse:
    state = request.app.state
    body = await _read_limited(request)
    if body is None:
        return _reply(413, error="payload too large")

    if not verify_signature(state.webhook_secret, body, request.headers.get("x-hub-signature-256")):
        log.warning("rejected webhook with a missing or invalid signature")
        return _reply(401, error="invalid signature")

    event = request.headers.get("x-github-event")
    delivery_id = request.headers.get("x-github-delivery")
    if not event or not delivery_id or len(delivery_id) > 64:
        return _reply(400, error="missing X-GitHub-Event or X-GitHub-Delivery")
    try:
        payload = json.loads(body)
    except ValueError:
        return _reply(400, error="body is not valid JSON")
    if not isinstance(payload, dict):
        return _reply(400, error="body is not a JSON object")

    digest = hashlib.sha256(body).hexdigest()
    return await run_in_threadpool(_process, state, event, delivery_id, payload, digest)


def _process(
    state: Any, event: str, delivery_id: str, payload: dict[str, Any], digest: str
) -> JSONResponse:
    with session_scope(state.session_factory) as session:
        inserted = session.execute(
            pg_insert(WebhookDelivery)
            .values(
                delivery_id=delivery_id,
                event=event,
                action=str(payload.get("action"))[:64] if payload.get("action") else None,
                payload_sha256=digest,
            )
            .on_conflict_do_nothing()
            .returning(WebhookDelivery.delivery_id)
        ).scalar_one_or_none()
        if inserted is None:
            log.info("duplicate delivery %s (%s) ignored", delivery_id, event)
            return _reply(200, status="duplicate")

        parsed = parse_event(event, payload, app_id=state.app_id, check_name=CHECK_NAME)
        result = apply_actions(session, parsed)
        delivery = session.get(WebhookDelivery, delivery_id)
        assert delivery is not None
        delivery.processed_at = utcnow()

    log.info(
        "delivery %s %s: jobs=%s superseded=%s %s",
        delivery_id,
        event,
        result.job_ids,
        result.superseded,
        "; ".join(result.notes),
    )
    status = 202 if result.job_ids else 200
    return _reply(
        status,
        status="queued" if result.job_ids else "ignored",
        jobs=result.job_ids,
        superseded=result.superseded,
        note="; ".join(result.notes) or None,
    )
