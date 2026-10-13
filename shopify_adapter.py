#!/usr/bin/env python3
"""Minimal server-side Shopify Admin API adapter.

Holds the Shopify app's Client ID + Client secret in server environment
configuration, performs the client_credentials token exchange through
Shopify's documented POST body, refreshes the Admin API token automatically,
and exposes authenticated read-only checks with sanitized responses.

Stdlib only. No third-party dependencies.

Environment:
    SHOPIFY_SHOP_DOMAIN    e.g. strongmedicinestudio.myshopify.com (required)
    SHOPIFY_CLIENT_ID      Dev Dashboard app Client ID (required)
    SHOPIFY_CLIENT_SECRET  Dev Dashboard app Client secret (required)
    ADAPTER_API_KEY        Bearer key this adapter requires from callers (required)
    ADAPTER_BIND           Bind address, default 127.0.0.1
    ADAPTER_PORT           Port, default 8765

Endpoints (all except /health require Authorization: Bearer <ADAPTER_API_KEY>):
    GET /health        {"ok": true}
    GET /shop          {"name": ..., "myshopify_domain": ...}
    GET /scopes        {"token_scope": ...|null,
                        "probes": {"read_products": {"ok": true}, ...}}
    GET /publications  {"publications": [{"id":..., "name":...}, ...]}
    GET /locations     {"locations": [{"id":..., "name":..., "city":..., "province":...}, ...]}

Failure contract: any transport error, any GraphQL error, or any missing
expected data returns HTTP 502 with {"error": <SANITIZED_CODE>,
"detail": <truncated safe detail>}. Success is only returned when the query
succeeded AND the expected data is present.

No response ever contains the client secret, the API key, or an access token.
Logs contain event types and HTTP statuses only, never credential values.
"""

import hmac
import json
import logging
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_VERSION = "2026-01"
TOKEN_TTL_SECONDS = 24 * 3600
REFRESH_AT_FRACTION = 0.8  # proactively refresh at 80% of TTL

log = logging.getLogger("shopify_adapter")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def _required_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        # Never print the value, only the name.
        log.error("missing required environment variable: %s", name)
        sys.exit(1)
    return value


SHOP_DOMAIN = _required_env("SHOPIFY_SHOP_DOMAIN")
CLIENT_ID = _required_env("SHOPIFY_CLIENT_ID")
CLIENT_SECRET = _required_env("SHOPIFY_CLIENT_SECRET")
ADAPTER_API_KEY = _required_env("ADAPTER_API_KEY")
BIND = os.environ.get("ADAPTER_BIND", "127.0.0.1").strip() or "127.0.0.1"
PORT = int(os.environ.get("ADAPTER_PORT", "8765").strip() or "8765")


# --------------------------------------------------------------------------
# Sanitized errors
# --------------------------------------------------------------------------

def _err(code, detail=""):
    """Build a sanitized error dict. Detail is truncated; never carries secrets."""
    error = {"error": code}
    detail = str(detail or "")[:200]
    if detail:
        error["detail"] = detail
    return error


# --------------------------------------------------------------------------
# Token manager: exchange via POST body, cache, auto-refresh
# --------------------------------------------------------------------------

class TokenManager:
    """Holds the current Admin API token. Thread-safe.

    Exchange uses Shopify's documented form body:
        grant_type=client_credentials&client_id=...&client_secret=...
    Refresh happens proactively (background thread, well before TTL expiry)
    and reactively (single retry on HTTP 401 from Shopify).

    Concurrency: all state changes happen under one lock. Concurrent callers
    block briefly during a refresh and then share the single fresh token;
    there is no thundering-herd of parallel exchanges and no stale token
    is ever returned. Network I/O under the lock is acceptable at this
    call volume.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._token = None
        self._expires_at = 0.0
        self._token_scope = None
        self._stop = threading.Event()
        self._refresher = threading.Thread(
            target=self._refresh_loop, name="token-refresher", daemon=True
        )

    def start(self):
        # Fail fast: if the exchange itself is broken, do not serve.
        self.refresh(force=True)
        self._refresher.start()

    def stop(self):
        self._stop.set()

    def _exchange(self):
        """POST the client credentials grant. Returns (token, expires_in, scope)."""
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"https://{SHOP_DOMAIN}/admin/oauth/access_token",
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                raw = e.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw)
                detail = parsed.get("error_description") or parsed.get("error") or ""
            except Exception:
                pass
            # Sanitized: status + Shopify's error string only, never the request.
            raise RuntimeError(f"token exchange failed: HTTP {e.code} {detail}".strip())
        token = payload.get("access_token")
        if not token:
            raise RuntimeError("token exchange returned no access_token")
        return token, int(payload.get("expires_in", TOKEN_TTL_SECONDS)), payload.get("scope")

    def _refresh_locked(self):
        token, expires_in, scope = self._exchange()
        self._token = token
        self._token_scope = scope
        self._expires_at = (
            time.time() + min(expires_in, TOKEN_TTL_SECONDS) * REFRESH_AT_FRACTION
        )
        log.info("admin token refreshed")

    def refresh(self, force=False):
        """Refresh if forced or expired. Safe to call from any thread."""
        with self._lock:
            if force or not self._token or time.time() >= self._expires_at:
                self._refresh_locked()

    def token(self):
        """Return a valid token, refreshing under lock when missing or expired."""
        with self._lock:
            if not self._token or time.time() >= self._expires_at:
                self._refresh_locked()
            return self._token

    def invalidate(self):
        with self._lock:
            self._token = None
            self._expires_at = 0.0

    @property
    def token_scope(self):
        with self._lock:
            return self._token_scope

    def _refresh_loop(self):
        while not self._stop.wait(60):
            try:
                self.refresh()
            except Exception as e:  # keep the loop alive; next tick retries
                log.warning("proactive refresh failed: %s", e)


TOKENS = TokenManager()


# --------------------------------------------------------------------------
# Shopify Admin API helpers (sanitized)
# --------------------------------------------------------------------------

def _graphql(query, variables=None):
    """Run one GraphQL query.

    Returns (data_dict|None, error_dict|None). Any transport failure, any
    GraphQL error, or any non-JSON response is a failure; error_dict carries
    a sanitized code, never credential material.
    """
    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")

    def _call(token):
        req = urllib.request.Request(
            f"https://{SHOP_DOMAIN}/admin/api/{API_VERSION}/graphql.json",
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Shopify-Access-Token": token,
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    try:
        result = _call(TOKENS.token())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            log.info("shopify returned 401; refreshing token and retrying once")
            TOKENS.invalidate()
            try:
                result = _call(TOKENS.token())
            except urllib.error.HTTPError as e2:
                return None, _err(f"HTTP_{e2.code}")
            except Exception:
                return None, _err("NETWORK_ERROR")
        else:
            return None, _err(f"HTTP_{e.code}")
    except Exception:
        return None, _err("NETWORK_ERROR")

    if not isinstance(result, dict):
        return None, _err("INVALID_RESPONSE")
    gql_errors = result.get("errors") or []
    if gql_errors:
        first = gql_errors[0] if isinstance(gql_errors[0], dict) else {}
        return None, _err("GRAPHQL_ERROR", first.get("message", ""))
    return result.get("data") or {}, None


# --------------------------------------------------------------------------
# Read-only checks. Every check fails closed: error or missing expected
# data -> (None, error). Success is only returned with complete data.
# --------------------------------------------------------------------------

def check_shop():
    data, err = _graphql("{ shop { name myshopifyDomain } }")
    if err:
        return None, err
    shop = data.get("shop") or {}
    if not shop.get("name") or not shop.get("myshopifyDomain"):
        return None, _err("MISSING_DATA", "shop.name or shop.myshopifyDomain absent")
    return {"name": shop["name"], "myshopify_domain": shop["myshopifyDomain"]}, None


# scope -> (expected root field, minimal query). Each query is chosen so that
# success proves the named permission is granted.
PROBES = {
    "read_products": (
        "products",
        "{ products(first: 1) { edges { node { id } } } }",
    ),
    "read_inventory": (
        "inventoryItems",
        "{ inventoryItems(first: 1) { edges { node { id } } } }",
    ),
    "read_publications": (
        "publications",
        "{ publications(first: 1) { edges { node { id } } } }",
    ),
    "read_locations": (
        "locations",
        "{ locations(first: 1) { edges { node { id } } } }",
    ),
}


def check_scopes():
    probes = {}
    for scope, (root_field, query) in PROBES.items():
        data, err = _graphql(query)
        if err:
            # Any GraphQL error (not just "access denied") is a failed probe.
            probes[scope] = {"ok": False, **err}
        elif not isinstance(data.get(root_field), dict):
            probes[scope] = {"ok": False, **_err("MISSING_DATA")}
        else:
            probes[scope] = {"ok": True}
    return {"token_scope": TOKENS.token_scope, "probes": probes}, None


def check_publications():
    data, err = _graphql("{ publications(first: 20) { edges { node { id name } } } }")
    if err:
        return None, err
    pubs = data.get("publications")
    if not isinstance(pubs, dict):
        return None, _err("MISSING_DATA", "publications connection absent")
    out = [
        {"id": p.get("id"), "name": p.get("name")}
        for p in (e.get("node") or {} for e in pubs.get("edges", []))
    ]
    return {"publications": out}, None


def check_locations():
    data, err = _graphql(
        "{ locations(first: 20) { edges { node { id name "
        "address { city provinceCode } } } } }"
    )
    if err:
        return None, err
    locs = data.get("locations")
    if not isinstance(locs, dict):
        return None, _err("MISSING_DATA", "locations connection absent")
    out = []
    for edge in locs.get("edges", []):
        node = edge.get("node") or {}
        addr = node.get("address") or {}
        out.append({
            "id": node.get("id"),
            "name": node.get("name"),
            "city": addr.get("city"),
            "province": addr.get("provinceCode"),
        })
    return {"locations": out}, None


CHECKS = {
    "shop": check_shop,
    "scopes": check_scopes,
    "publications": check_publications,
    "locations": check_locations,
}


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "ShopifyAdapter/1.0"

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return hmac.compare_digest(auth[len("Bearer "):].strip(), ADAPTER_API_KEY)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/health":
            self._send(200, {"ok": True})
            return
        if not self._authorized():
            self._send(401, {"error": "UNAUTHORIZED"})
            return
        name = path.lstrip("/")
        check = CHECKS.get(name)
        if not check:
            self._send(404, {"error": "UNKNOWN_ENDPOINT"})
            return
        try:
            result, err = check()
        except Exception as e:  # never leak internals
            log.warning("check %s raised %s", name, type(e).__name__)
            self._send(502, _err("CHECK_FAILED"))
            return
        if err:
            log.info("check %s failed: %s", name, err.get("error"))
            self._send(502, err)
            return
        self._send(200, result)

    def log_message(self, fmt, *args):
        # Access log without query strings or headers.
        log.info("%s %s", self.command, urllib.parse.urlsplit(self.path).path)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    try:
        TOKENS.start()
    except Exception as e:
        log.error("initial token exchange failed: %s", e)
        sys.exit(1)
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    log.info("listening on %s:%d (shopify shop: %s)", BIND, PORT, SHOP_DOMAIN)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        TOKENS.stop()
        server.server_close()


if __name__ == "__main__":
    main()
