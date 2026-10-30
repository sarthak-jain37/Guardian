"""Authenticated analysis API. Worker writes require a live fenced lease."""
import asyncio
import sqlite3
from fastapi import APIRouter, HTTPException, Query, Request
from backend.app.core.auth import Authenticated
from backend.app.models.analysis import AnalysisIntake, JobClaim, JobLease, JobComplete, BudgetRequest, ReportDecision
from backend.app.services.governance_store import LedgerError

router=APIRouter(prefix='/analysis',tags=['analysis'])


async def call(request,operation,*args):
    store=getattr(request.app.state,'analysis',None)
    if store is None:raise HTTPException(503,'analysis_not_configured')
    try:return await asyncio.to_thread(getattr(store,operation),*args)
    except LedgerError as error:raise HTTPException(error.status,error.code) from None
    except (sqlite3.Error,OSError):raise HTTPException(503,'analysis_storage_unavailable') from None
    except (ValueError,LookupError):raise HTTPException(422,'analysis_contract_or_scope_invalid') from None


@router.post('/runs',status_code=202)
async def create(request:Request,body:AnalysisIntake,principal:Authenticated):
    if body.cluster_id!=getattr(request.app.state,'analysis_cluster_id',None):
        raise HTTPException(403,'cluster_not_configured')
    if principal.kind=='human' and body.trigger in ('drift','periodic'):
        raise HTTPException(422,'automatic_trigger_requires_backend_scheduler')
    return await call(request,'enqueue',body,principal)


@router.get('/runs')
async def runs(request:Request,principal:Authenticated,cluster_id:str,namespace:str,
               limit:int=Query(50,ge=1,le=100)):
    return {'runs':await call(request,'list',cluster_id,namespace,principal,limit)}


@router.get('/runs/{run_id}')
async def get(request:Request,run_id:str,principal:Authenticated):
    return await call(request,'get',run_id,principal)


@router.get('/runs/{run_id}/history')
async def history(request:Request,run_id:str,principal:Authenticated,after_sequence:int=Query(0,ge=0)):
    rows=await call(request,'history',run_id,principal,after_sequence)
    return {'history':rows,'next_after_sequence':rows[-1]['sequence'] if rows else after_sequence}


@router.post('/runs/{run_id}/decisions')
async def decide(request:Request,run_id:str,body:ReportDecision,principal:Authenticated):
    return await call(request,'decide',run_id,body,principal)


@router.post('/jobs/claim')
async def claim(request:Request,body:JobClaim,principal:Authenticated):
    return {'job':await call(request,'claim',body,principal)}


@router.post('/jobs/{run_id}/renew')
async def renew(request:Request,run_id:str,body:JobLease,principal:Authenticated):
    return await call(request,'renew',run_id,body.lease_token,principal)


@router.post('/jobs/{run_id}/complete')
async def complete(request:Request,run_id:str,body:JobComplete,principal:Authenticated):
    return await call(request,'complete',run_id,body,principal)


@router.post('/jobs/{run_id}/budget')
async def budget(request:Request,run_id:str,body:BudgetRequest,principal:Authenticated):
    return {'value':await call(request,'budget',run_id,body,principal)}
