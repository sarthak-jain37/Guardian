"""Uncached per-session authenticated review requests; token never enters a URL."""
import requests


class ReviewClient:
    def __init__(self,base,token):self.base,self.token=base.rstrip('/'),token

    def call(self,method,path,*,body=None,params=None,timeout=20):
        response=requests.request(method,self.base+path,params=params,json=body,
            headers={'Authorization':'Bearer '+self.token},timeout=timeout,allow_redirects=False)
        if len(response.content)>2*1024*1024:raise ValueError('Review response exceeds display limit')
        if not 200<=response.status_code<300:
            try:code=response.json()['detail']
            except (ValueError,KeyError):code='backend_unavailable'
            if not isinstance(code,str):code='invalid_request'
            raise ValueError(f'Request failed ({response.status_code}): {code}')
        return response.json()
