"""Scoped evidence access; no raw archive paths/keys are exposed to clients."""
import asyncio
from fastapi import APIRouter, HTTPException, Request
from backend.app.core.auth import Authenticated
from backend.app.models.evidence import UsageQuery
from backend.app.services.audit_usage import iso

router=APIRouter(prefix='/evidence',tags=['evidence'])


async def source(request):
    usage=getattr(request.app.state,'usage',None)
    if usage is None:raise HTTPException(503,'evidence_store_unavailable')
    return usage


@router.post('/usage')
async def usage_query(request:Request,body:UsageQuery,principal:Authenticated):
    principal.require('read',body.cluster_id,body.namespace)
    usage=await source(request)
    try:return (await asyncio.to_thread(usage.query,body)).model_dump(mode='json')
    except ValueError:raise HTTPException(422,'invalid_or_unavailable_usage_query') from None


@router.get('/snapshots/{snapshot_id}')
async def snapshot(request:Request,snapshot_id:str,principal:Authenticated):
    inventory=getattr(request.app.state,'evidence_inventory',None)
    if inventory is None:raise HTTPException(503,'inventory_unavailable')
    try:value=await asyncio.to_thread(inventory.load,snapshot_id)
    except LookupError:raise HTTPException(404,'snapshot_not_found') from None
    principal.require('read',value.target.cluster_id,value.target.namespace)
    return value.model_dump(mode='json')


@router.get('/roles')
async def roles(request:Request,cluster_id:str,namespace:str,principal:Authenticated):
    principal.require('read',cluster_id,namespace)
    configured=getattr(request.app.state,'analysis_cluster_id',None)
    if cluster_id!=configured:raise HTTPException(403,'cluster_not_configured')
    state=await asyncio.to_thread(request.app.state.k8s.get_rbac_state)
    return {'roles':[{'name':o['metadata']['name'],'uid':o['metadata'].get('uid'),
            'resource_version':o['metadata'].get('resourceVersion')} for o in state.values()
            if o.get('kind')=='Role' and o.get('metadata',{}).get('namespace')==namespace]}


@router.post('/archive-query')
async def archive_query(request:Request,body:UsageQuery,principal:Authenticated):
    principal.require('read',body.cluster_id,body.namespace)
    archive=getattr(request.app.state,'evidence_archive',None)
    if archive is None:raise HTTPException(503,'archive_keys_or_storage_unavailable')
    usage=await source(request)
    def restore():
        with usage.db.transaction() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS evidence_access (
                actor TEXT,cluster_id TEXT,namespace TEXT,operation TEXT,recorded_at TEXT)''')
            db.execute('INSERT INTO evidence_access VALUES (?,?,?,?,?)',
                (principal.actor,body.cluster_id,body.namespace,'archive_query',iso(usage.clock())))
        return archive.restore(body)
    return await asyncio.to_thread(restore)
