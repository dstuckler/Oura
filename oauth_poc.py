"""Proof of concept: one hosted Oura connector, many users, no stored data.

THIS IS A THROWAWAY. It exists to answer one question before any of it is
built for real: can Claude's connector complete an OAuth handshake against a
FastMCP server that brokers a third-party login, with the resulting token
living in the client rather than on our disk?

The design under test
---------------------
The MCP access token IS the user's Oura access token. Nothing translates
between them and nothing is written down:

  1. Claude discovers this server needs auth and registers itself
  2. Claude opens /authorize; we redirect to Oura's consent screen
  3. the user logs in with THEIR Oura account
  4. Oura redirects to /oura/callback; we swap the code for Oura tokens
  5. we hand those tokens to Claude as the MCP tokens and forget them
  6. later calls arrive bearing the user's Oura token; we forward it

So the server holds no health data and no long-lived credential. What it does
hold, for minutes at a time and in memory only, is the in-flight authorisation
state: a registered client, a pending code. A restart loses those and any
half-finished login has to be restarted. That is the intended trade.

What this does NOT establish, and must not be taken as proving:
  - production readiness. In-memory client registration means a restart
    forgets every client, which real users would feel as a re-login.
  - Oura's 10-user cap. That is a business gate, unaffected by any of this.
  - that data never touches the server. It does, in transit, on every call.
    The claim this supports is "never stored", not "never seen".
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from mcp.server.auth.provider import (AccessToken, AuthorizationCode,
                                      AuthorizationParams,
                                      OAuthAuthorizationServerProvider,
                                      RefreshToken)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("oura-oauth-poc")

CLIENT_ID = os.environ.get("OURA_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("OURA_CLIENT_SECRET", "").strip()
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")

OURA_AUTHORIZE_URL = "https://cloud.ouraring.com/oauth/authorize"
OURA_TOKEN_URL = "https://api.ouraring.com/oauth/token"
OURA_API = "https://api.ouraring.com/v2"
SCOPES = ["email", "personal", "daily", "heartrate", "workout", "tag",
          "session", "spo2Daily", "spo2"]

TIMEOUT = httpx.Timeout(20.0, connect=10.0)
STATE_TTL = 600


class OuraBroker(OAuthAuthorizationServerProvider):
    """Brokers Claude's OAuth flow onto Oura's, keeping nothing durable.

    Every dict here is deliberately in memory. Persisting them would mean
    holding credentials that belong to the user, which is the exact thing this
    design exists to avoid. The cost is that a restart drops in-flight logins
    and registered clients.
    """

    def __init__(self) -> None:
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.flows: dict[str, tuple[OAuthClientInformationFull,
                                    AuthorizationParams, float]] = {}
        self.codes: dict[str, tuple[AuthorizationCode, dict]] = {}

    # --- client registration ---------------------------------------------

    async def get_client(self, client_id: str):
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        self.clients[client_info.client_id] = client_info
        log.info("registered client %s", client_info.client_id)

    # --- authorisation ----------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull,
                        params: AuthorizationParams) -> str:
        """Send the user to Oura rather than showing a login of our own.

        Claude's state and PKCE challenge are parked against a state value of
        our own, because Oura will hand back only what we give it.
        """
        state = secrets.token_urlsafe(24)
        self._sweep()
        self.flows[state] = (client, params, time.time() + STATE_TTL)
        return f"{OURA_AUTHORIZE_URL}?" + urlencode({
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": f"{PUBLIC_URL}/oura/callback",
            "scope": " ".join(SCOPES),
            "state": state,
        })

    async def load_authorization_code(self, client, authorization_code: str):
        entry = self.codes.get(authorization_code)
        if not entry:
            return None
        code, _tokens = entry
        if code.client_id != client.client_id or code.expires_at < time.time():
            return None
        return code

    async def exchange_authorization_code(self, client,
                                          authorization_code) -> OAuthToken:
        """Hand Claude the Oura tokens themselves, then drop our copy."""
        entry = self.codes.pop(authorization_code.code, None)
        if not entry:
            raise ValueError("unknown or already-used authorization code")
        _code, tokens = entry
        return OAuthToken(
            access_token=tokens["access_token"],
            refresh_token=tokens.get("refresh_token"),
            expires_in=tokens.get("expires_in", 86400),
            scope=" ".join(SCOPES),
        )

    # --- tokens -----------------------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Accept the bearer without local verification.

        The token is Oura's, not ours: we hold no key to check it against and
        no record of having issued it. Verifying would mean a round trip to
        Oura on every request. Instead the real check happens where it counts,
        when the forwarded token is used and Oura accepts or refuses it. A
        forged token gets past this line and straight into a 401 from Oura.
        """
        if not token:
            return None
        return AccessToken(token=token, client_id="oura", scopes=SCOPES)

    async def load_refresh_token(self, client, refresh_token: str):
        return RefreshToken(token=refresh_token,
                            client_id=client.client_id, scopes=SCOPES)

    async def exchange_refresh_token(self, client, refresh_token,
                                     scopes: list[str]) -> OAuthToken:
        """Proxy the refresh to Oura. Our client secret never leaves here."""
        async with httpx.AsyncClient(timeout=TIMEOUT) as http:
            r = await http.post(OURA_TOKEN_URL, data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token.token,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            })
            r.raise_for_status()
            t = r.json()
        return OAuthToken(
            access_token=t["access_token"],
            refresh_token=t.get("refresh_token", refresh_token.token),
            expires_in=t.get("expires_in", 86400),
            scope=" ".join(SCOPES),
        )

    async def revoke_token(self, token) -> None:
        # Nothing stored, so nothing to revoke here. The user revokes access
        # in their own Oura account, which is the correct place for it.
        return None

    def _sweep(self) -> None:
        now = time.time()
        self.flows = {k: v for k, v in self.flows.items() if v[2] > now}
        self.codes = {k: v for k, v in self.codes.items()
                      if v[0].expires_at > now}


broker = OuraBroker()

mcp = FastMCP(
    "oura-multiuser-poc",
    instructions=("Proof of concept. Each user authenticates with their own "
                  "Oura account; the server stores nothing."),
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8000")),
    stateless_http=True,
    auth_server_provider=broker,
    auth=AuthSettings(
        issuer_url=PUBLIC_URL or "https://example.invalid",
        resource_server_url=PUBLIC_URL or "https://example.invalid",
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=SCOPES, default_scopes=SCOPES),
    ),
)


@mcp.custom_route("/oura/callback", methods=["GET"])
async def oura_callback(request: Request) -> Any:
    """Where Oura returns the user. Swap their code for tokens, then send
    Claude an authorisation code of ours that stands for those tokens."""
    err = request.query_params.get("error")
    if err:
        return PlainTextResponse(f"Oura refused: {err}", status_code=400)
    oura_code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    entry = broker.flows.pop(state, None)
    if not oura_code or not entry:
        return PlainTextResponse("Invalid or expired login. Start again.",
                                 status_code=400)
    client, params, _exp = entry
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as http:
            r = await http.post(OURA_TOKEN_URL, data={
                "grant_type": "authorization_code",
                "code": oura_code,
                "redirect_uri": f"{PUBLIC_URL}/oura/callback",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            })
            if r.status_code >= 400:
                log.warning("Oura token exchange failed: %s", r.status_code)
                return PlainTextResponse(
                    f"Oura rejected the exchange (HTTP {r.status_code}). The "
                    f"redirect URI must be exactly {PUBLIC_URL}/oura/callback",
                    status_code=400)
            tokens = r.json()
    except Exception as e:  # noqa: BLE001
        log.warning("callback failed: %s", type(e).__name__)
        return PlainTextResponse(f"Login failed: {type(e).__name__}",
                                 status_code=500)

    our_code = secrets.token_urlsafe(32)
    broker.codes[our_code] = (
        AuthorizationCode(
            code=our_code,
            scopes=SCOPES,
            expires_at=time.time() + 300,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
        ),
        tokens,
    )
    sep = "&" if "?" in str(params.redirect_uri) else "?"
    back = f"{params.redirect_uri}{sep}code={our_code}"
    if params.state:
        back += f"&state={params.state}"
    return RedirectResponse(back)


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> PlainTextResponse:
    return PlainTextResponse(
        f"ok poc clients={len(broker.clients)} "
        f"flows={len(broker.flows)} codes={len(broker.codes)}")


async def _oura_get(path: str, params: dict) -> dict:
    """Forward the caller's own token. No token of ours is involved."""
    tok = get_access_token()
    if tok is None:
        raise RuntimeError("no access token on this request")
    async with httpx.AsyncClient(timeout=TIMEOUT) as http:
        r = await http.get(f"{OURA_API}{path}", params=params,
                           headers={"Authorization": f"Bearer {tok.token}"})
        r.raise_for_status()
        return r.json()


@mcp.tool()
async def whoami() -> dict:
    """Confirm whose Oura account this connector is reading. Returns the
    signed-in user's own profile, proving the token belongs to the caller and
    not to whoever deployed the server."""
    try:
        me = await _oura_get("/usercollection/personal_info", {})
        return {"authenticated_as": me.get("email"), "age": me.get("age"),
                "note": "This came from YOUR Oura account, via YOUR token. "
                        "The server stored nothing."}
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
async def recent_sleep(days: int = 5) -> dict:
    """A few nights of the signed-in user's own sleep, to show real data
    flowing through a token the server never kept."""
    from datetime import date, timedelta
    end = date.today()
    start = end - timedelta(days=max(1, min(days, 30)) - 1)
    try:
        data = await _oura_get("/usercollection/daily_sleep",
                               {"start_date": start.isoformat(),
                                "end_date": end.isoformat()})
        return {"nights": [{"day": d.get("day"), "score": d.get("score")}
                           for d in data.get("data", [])]}
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


if __name__ == "__main__":
    import uvicorn
    if not PUBLIC_URL.startswith("https://"):
        log.warning("PUBLIC_URL is not https; the OAuth flow will fail")
    uvicorn.run(mcp.streamable_http_app(),
                host=mcp.settings.host, port=mcp.settings.port)
