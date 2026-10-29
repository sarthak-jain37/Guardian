"""Authenticated governance API. There is deliberately no execute endpoint yet."""
import asyncio
import sqlite3

from fastapi import APIRouter, HTTPException, Query, Request

from backend.app.core.auth import Authenticated
from backend.app.models.governance import DecisionInput, DeliveryAck, DeliveryClaim, HoldInput, ReviewPublication
from backend.app.services.governance_store import LedgerError

router = APIRouter(prefix="/governance", tags=["governance"])


async def call(request, operation, *args):
    store = getattr(request.app.state, "governance", None)
    if store is None:
        raise HTTPException(503, "governance_not_configured")
    try:
        return await asyncio.to_thread(getattr(store, operation), *args)
    except LedgerError as error:
        raise HTTPException(error.status, error.code) from None
    except sqlite3.Error:
        # Never return DB paths, raw payloads or SQL details to clients.
        raise HTTPException(503, "governance_storage_unavailable") from None


@router.get("/me")
async def me(principal: Authenticated):
    return {"principal": principal.model_dump(), "execution_available": False}


@router.post("/reviews")
async def publish(request: Request, body: ReviewPublication, principal: Authenticated):
    return await call(request, "publish_review", body, principal)


@router.get("/reviews")
async def reviews(request: Request, principal: Authenticated, cluster_id: str, namespace: str,
                  limit: int = Query(100, ge=1, le=100)):
    return {"reviews": await call(request, "list_reviews", cluster_id, namespace, principal, limit)}


@router.get("/reviews/{proposal_id}")
async def review(request: Request, proposal_id: str, principal: Authenticated):
    return await call(request, "get_review", proposal_id, principal)


@router.get("/reviews/{proposal_id}/history")
async def history(request: Request, proposal_id: str, principal: Authenticated,
                  after_sequence: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=100)):
    records = await call(request, "history", proposal_id, principal, after_sequence, limit)
    return {"history": records, "next_after_sequence": records[-1]["sequence"] if records else after_sequence}


@router.post("/reviews/{proposal_id}/decisions")
async def decide(request: Request, proposal_id: str, body: DecisionInput, principal: Authenticated):
    return await call(request, "record_decision", proposal_id, body, principal)


@router.get("/decisions/{decision_id}")
async def decision(request: Request, decision_id: str, principal: Authenticated):
    return await call(request, "get_decision", decision_id, principal)


@router.post("/deliveries/claim")
async def claim(request: Request, body: DeliveryClaim, principal: Authenticated):
    return {"deliveries": await call(request, "claim_deliveries", body, principal)}


@router.post("/deliveries/{delivery_id}/ack")
async def acknowledge(request: Request, delivery_id: str, body: DeliveryAck, principal: Authenticated):
    return await call(request, "acknowledge_delivery", delivery_id, body.lease_token, principal)


@router.post("/holds")
async def hold(request: Request, body: HoldInput, principal: Authenticated):
    return await call(request, "record_hold", body, principal)


@router.get("/holds")
async def holds(request: Request, principal: Authenticated, cluster_id: str, namespace: str):
    return await call(request, "get_holds", cluster_id, namespace, principal)
