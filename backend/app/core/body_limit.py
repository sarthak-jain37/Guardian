"""Bound governance request bodies before JSON/schema parsing."""
from starlette.responses import JSONResponse

MAX_GOVERNANCE_BODY_BYTES = 2 * 1024 * 1024


class GovernanceBodyLimit:
    def __init__(self, app, maximum=MAX_GOVERNANCE_BODY_BYTES):
        self.app, self.maximum = app, maximum

    async def __call__(self, scope, receive, send):
        if (scope["type"] != "http" or scope.get("method") != "POST"
                or not scope.get("path", "").startswith("/governance/")):
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.maximum:
                return await JSONResponse({"detail": "governance_body_too_large"}, status_code=413)(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        return await self.app(scope, bounded_receive, send)
