"""Authenticate before parsing bodies; bound body size and event request rate."""
from collections import deque
import hmac
import json
from time import monotonic

from starlette.responses import JSONResponse


class BoundaryMiddleware:
    def __init__(self, app, config):
        self.app, self.config = app, config
        self.arrivals = deque()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        if path in ("/health", "/docs", "/docs/oauth2-redirect", "/openapi.json", "/redoc"):
            return await self.app(scope, receive, send)

        async def fail(code, reason, headers=None):
            await JSONResponse({"detail": reason}, status_code=code, headers=headers)(scope, receive, send)

        event_route = path.rstrip("/") == "/v1/behavior-events"
        expected = self.config.service_token if event_route else self.config.admin_token
        if not expected:
            return await fail(503, "required service credential is not configured")
        auth = [v for k, v in scope["headers"] if k.lower() == b"authorization"]
        supplied = auth[0].decode("latin1") if len(auth) == 1 else ""
        scheme, _, token = supplied.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(token.encode(), expected.encode()):
            return await fail(401, "invalid or missing bearer credential", {"WWW-Authenticate": "Bearer"})
        if event_route:
            now = monotonic()
            while self.arrivals and self.arrivals[0] <= now - 60:
                self.arrivals.popleft()
            if len(self.arrivals) >= self.config.events_per_minute:
                return await fail(429, "event request rate limit reached", {"Retry-After": "60"})
            self.arrivals.append(now)
        if scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.config.max_body_bytes:
                return await fail(413, "request body exceeds configured byte limit")
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        if event_route:
            headers = dict(scope["headers"])
            if headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower() != b"application/json":
                return await fail(415, "use Content-Type: application/json")

            def reject_constant(value):
                raise ValueError("non-finite JSON number")

            def unique_keys(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON key")
                    result[key] = value
                return result

            try:
                parsed = json.loads(body, parse_constant=reject_constant, object_pairs_hook=unique_keys)
                # Reject overflow and lone Unicode surrogates before fingerprints
                # or UTF-8 evidence encoding can fail inside the transaction path.
                json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode("utf-8")
            except (ValueError, UnicodeError, RecursionError):
                return await fail(400, "malformed JSON, duplicate keys or non-finite numbers")
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
