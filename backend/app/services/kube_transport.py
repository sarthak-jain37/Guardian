"""Small version-aware synchronous transport with per-request audit identity.

ApiClient 36 uses response_types_map; earlier SDKs used response_type. Its default
headers override request headers, so clone the header dictionary for a tagged
request while sharing the owner's thread-safe connection pool. No global header
mutation or owned-pool close occurs during the request.
"""
from copy import copy
from inspect import signature


def api_call(api,path,method,*,response_type='object',user_agent=None,**kwargs):
    request=api
    if user_agent:
        request=copy(api);request.default_headers=dict(api.default_headers)
        request.user_agent=user_agent
        kwargs['header_params']={**kwargs.get('header_params',{}),'User-Agent':user_agent}
    if 'response_types_map' in signature(request.call_api).parameters:
        kwargs['response_types_map']={code:response_type for code in (200,201,202)}
    else:kwargs['response_type']=response_type
    return request.call_api(path,method,**kwargs)
