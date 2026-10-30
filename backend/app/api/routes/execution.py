"""Scoped governed action routes; callers never supply rules, YAML or commands."""
import asyncio
import sqlite3
from fastapi import APIRouter,HTTPException,Request
from backend.app.core.auth import Authenticated
from backend.app.models.execution import PrepareReview,RevokeAuthority,FreshRecovery,ExecutionRequest
from backend.app.services.governance_store import LedgerError

router=APIRouter(prefix='/execution',tags=['execution'])


async def call(request,method,*args):
    store=getattr(request.app.state,'execution',None)
    if store is None:raise HTTPException(503,'governed_executor_unavailable')
    try:return await asyncio.to_thread(getattr(store,method),*args)
    except LedgerError as error:raise HTTPException(error.status,error.code) from None
    except (sqlite3.Error,OSError):raise HTTPException(503,'execution_storage_unavailable') from None
    except (ValueError,LookupError):raise HTTPException(422,'execution_contract_invalid') from None


@router.get('/capabilities')
async def capabilities(request:Request,principal:Authenticated,cluster_id:str,namespace:str):
    principal.require('read',cluster_id,namespace)
    store=getattr(request.app.state,'execution',None)
    enabled=bool(store and store.enabled and cluster_id==store.policy.cluster_id and namespace in store.policy.namespaces
        and namespace in store.inventory.controlled)
    return {'execution_available':enabled,'recovery_mode':store.policy.recovery_mode if store else None,
        'automatic_recovery_default':False,'scope':'one_existing_dedicated_namespaced_role'}


@router.post('/reviews',status_code=202)
async def prepare(request:Request,body:PrepareReview,principal:Authenticated):
    return await call(request,'submit',body,principal)


@router.get('/preparations/{identifier}')
async def preparation(request:Request,identifier:str,principal:Authenticated):
    return await call(request,'preparation',identifier,principal)


@router.get('/reviews')
async def reviews(request:Request,principal:Authenticated,cluster_id:str,namespace:str):
    return {'reviews':await call(request,'list_reviews',cluster_id,namespace,principal)}


@router.get('/reviews/{proposal_id}')
async def review(request:Request,proposal_id:str,principal:Authenticated):
    return await call(request,'review_detail',proposal_id,principal)


@router.post('/requests',status_code=202)
async def execution_request(request:Request,body:ExecutionRequest,principal:Authenticated):
    return await call(request,'request_execution',body,principal)


@router.post('/decisions/{decision_id}/revoke')
async def revoke(request:Request,decision_id:str,body:RevokeAuthority,principal:Authenticated):
    return await call(request,'revoke',decision_id,body,principal)


@router.post('/actions/{key}/recovery',status_code=202)
async def fresh_recovery(request:Request,key:str,body:FreshRecovery,principal:Authenticated):
    return await call(request,'fresh_recovery',key,body,principal)


@router.get('/notifications')
async def notices(request:Request,principal:Authenticated,cluster_id:str,namespace:str):
    return {'notifications':await call(request,'notifications',cluster_id,namespace,principal)}


@router.post('/notifications/{identifier}/ack')
async def acknowledge(request:Request,identifier:str,principal:Authenticated):
    return await call(request,'acknowledge_notification',identifier,principal)


@router.get('/baselines')
async def baselines(request:Request,principal:Authenticated,cluster_id:str,namespace:str):
    return {'baselines':await call(request,'baselines',cluster_id,namespace,principal)}


@router.post('/preflight')
async def preflight(request:Request,body:ExecutionRequest,principal:Authenticated):
    return await call(request,'preflight',body,principal)


@router.get('/receipts/{key}')
async def receipt(request:Request,key:str,principal:Authenticated):
    return await call(request,'receipt',key,principal)
