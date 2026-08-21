"""Oura connector for many users, holding nobody's health data.

Run:  python oura_multiuser.py     (streamable-http on HOST:PORT, path /mcp)
Env:  OURA_CLIENT_ID, OURA_CLIENT_SECRET, PUBLIC_URL

The single-user sibling, oura_mcp.py, keeps one Oura token on a disk and puts
a shared secret on the door. That is the right shape for one person and it
stays as it is. This file is for handing the tool to other people, where
holding their tokens would make the operator custodian of other people's
health records.

How it differs
--------------
The MCP access token IS the user's Oura access token. Claude registers itself,
/authorize redirects to Oura, the callback swaps the code for Oura tokens and
returns them to Claude as the MCP tokens. Later calls arrive bearing the
user's own token, which is forwarded to Oura unchanged. Nothing durable is
written.

Every tool comes from oura_mcp.py unchanged. Only the token source differs,
through the TOKEN_PROVIDER hook there: the single-user server reads a disk,
this one reads the request. There is deliberately no second copy of the tool
bodies, because two copies of parsing logic for health data would drift and
the drift would be silent.

What this does and does not claim
---------------------------------
Nothing is stored: no token, no health record, no database, no disk. That
claim is true and is the point of the design.

Data still passes through this process in memory on every call. "We never
store your data" is honest; "your data never touches our servers" would not
be. Never log request or response bodies, and say the true version in any
privacy policy.

Known limits, both real:
  - Registered clients live in memory, so a restart signs everyone out. This
    is the piece that must be persisted before real use. See MULTIUSER.md.
  - Oura caps an unapproved application at 10 users.
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (AccessToken, AuthorizationCode,
                                      AuthorizationParams,
                                      OAuthAuthorizationServerProvider,
                                      RefreshToken)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse

# The single-user server is imported for its tools, its parsing and its error
# handling. Importing it builds an unused FastMCP instance of its own, which
# is harmless: its routes are registered on that instance, not on this one,
# and its disk paths are never touched because TOKEN_PROVIDER is set below.
import oura_mcp as core

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("oura-multiuser")

CLIENT_ID = os.environ.get("OURA_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("OURA_CLIENT_SECRET", "").strip()
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")

SCOPES = core.SCOPES
TIMEOUT = core.HTTP_TIMEOUT
STATE_TTL = 600
CODE_TTL = 300


async def _token_from_request() -> str:
    """The caller's own Oura token, taken off this request.

    Replaces the disk lookup in oura_mcp.py. Each request carries its own
    credential, so there is no per-user state here to keep, and none to leak
    between users.
    """
    tok = get_access_token()
    if tok is None:
        raise RuntimeError(
            "Not signed in to Oura. Reconnect this connector to log in.")
    return tok.token


core.TOKEN_PROVIDER = _token_from_request


class OuraBroker(OAuthAuthorizationServerProvider):
    """Brokers Claude's OAuth flow onto Oura's, keeping nothing durable."""

    def __init__(self) -> None:
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.flows: dict[str, tuple[OAuthClientInformationFull,
                                    AuthorizationParams, float]] = {}
        self.codes: dict[str, tuple[AuthorizationCode, dict]] = {}

    async def get_client(self, client_id: str):
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        self.clients[client_info.client_id] = client_info
        log.info("registered client %s", client_info.client_id)

    async def authorize(self, client: OAuthClientInformationFull,
                        params: AuthorizationParams) -> str:
        """Send the user to Oura rather than showing a login of our own."""
        state = secrets.token_urlsafe(24)
        self._sweep()
        self.flows[state] = (client, params, time.time() + STATE_TTL)
        return f"{core.OURA_AUTHORIZE_URL}?" + urlencode({
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

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Accept the bearer without local verification.

        The token is Oura's, not ours: there is no key here to check it
        against and no record of having issued it, and verifying would cost a
        round trip to Oura on every request. The real check happens where it
        counts, when the forwarded token is used and Oura accepts or refuses
        it. A forged token gets past this line and straight into a 401 from
        Oura, having reached nobody's data on the way.
        """
        if not token:
            return None
        return AccessToken(token=token, client_id="oura", scopes=SCOPES)

    async def load_refresh_token(self, client, refresh_token: str):
        return RefreshToken(token=refresh_token,
                            client_id=client.client_id, scopes=SCOPES)

    async def exchange_refresh_token(self, client, refresh_token,
                                     scopes: list[str]) -> OAuthToken:
        """Proxy the refresh to Oura. The client secret never leaves here."""
        async with httpx.AsyncClient(timeout=TIMEOUT) as http:
            r = await http.post(core.OURA_TOKEN_URL, data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token.token,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            })
            r.raise_for_status()
            t = r.json()
        return OAuthToken(
            access_token=t["access_token"],
            # Keep the old refresh token when Oura returns none, rather than
            # replacing it with nothing and locking the user out.
            refresh_token=t.get("refresh_token", refresh_token.token),
            expires_in=t.get("expires_in", 86400),
            scope=" ".join(SCOPES),
        )

    async def revoke_token(self, token) -> None:
        # Nothing is stored, so there is nothing here to revoke. Access is
        # withdrawn in the user's own Oura account, which is the right place
        # for it and the only place that actually ends it.
        return None

    def _sweep(self) -> None:
        now = time.time()
        self.flows = {k: v for k, v in self.flows.items() if v[2] > now}
        self.codes = {k: v for k, v in self.codes.items()
                      if v[0].expires_at > now}


broker = OuraBroker()

_INSTRUCTIONS = (
    "Read-only access to the signed-in user's own Oura Ring record: sleep, "
    "readiness, activity, stress, overnight breathing and SpO2, heart rate, "
    "workouts and travel. Report the numbers returned and their trend. Do not "
    "offer diagnosis. If a response reports missing fields, say so plainly "
    "rather than treating a missing value as a low reading. Every call reads "
    "the account of whoever signed in, and nothing is stored by the server."
)

mcp = FastMCP(
    "oura",
    instructions=_INSTRUCTIONS,
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

# The same tool objects the single-user server exposes, registered here.
# Listed explicitly rather than discovered, so adding a tool to oura_mcp.py is
# a deliberate decision to expose it to other people as well.
TOOLS = (
    core.check_connection,
    core.get_sleep,
    core.get_readiness,
    core.get_breathing,
    core.get_activity,
    core.get_stress,
    core.get_cardiovascular,
    core.get_heart_rate,
    core.get_workouts,
    core.get_sessions,
    core.compare_periods,
    core.find_travel_periods,
    core.list_available_data,
    core.get_raw,
)
for _fn in TOOLS:
    mcp.tool()(_fn)


@mcp.custom_route("/oura/callback", methods=["GET"])
async def oura_callback(request: Request) -> Any:
    """Where Oura returns the user. Swap their code for tokens, then send
    Claude an authorisation code of ours standing for those tokens."""
    err = request.query_params.get("error")
    if err:
        return PlainTextResponse(f"Oura refused: {err}", status_code=400)
    oura_code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    entry = broker.flows.pop(state, None)
    if not oura_code or not entry:
        return PlainTextResponse(
            "Invalid or expired login. Start again from your connector.",
            status_code=400)
    client, params, _exp = entry
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as http:
            r = await http.post(core.OURA_TOKEN_URL, data={
                "grant_type": "authorization_code",
                "code": oura_code,
                "redirect_uri": f"{PUBLIC_URL}/oura/callback",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            })
            if r.status_code >= 400:
                # Status code only. The body of a failed token exchange can
                # echo credentials.
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
            expires_at=time.time() + CODE_TTL,
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
    """Liveness plus the transient counts. Deliberately exposes no identity:
    these are sizes of in-memory dicts, not users."""
    return PlainTextResponse(
        f"ok multiuser {core.VERSION} tools={len(TOOLS)} "
        f"clients={len(broker.clients)} flows={len(broker.flows)}")


if __name__ == "__main__":
    import uvicorn

    missing = [n for n, v in (("OURA_CLIENT_ID", CLIENT_ID),
                              ("OURA_CLIENT_SECRET", CLIENT_SECRET),
                              ("PUBLIC_URL", PUBLIC_URL)) if core._unset(v)]
    if missing:
        raise SystemExit(
            "Refusing to start, not configured: " + ", ".join(missing))
    if not PUBLIC_URL.startswith("https://"):
        raise SystemExit(
            "PUBLIC_URL must be https. OAuth redirects and bearer tokens over "
            "plain http would put other people's health credentials on the "
            "wire in clear.")

    uvicorn.run(mcp.streamable_http_app(),
                host=mcp.settings.host, port=mcp.settings.port)
