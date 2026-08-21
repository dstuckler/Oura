"""Oura MCP connector — personal health data, single user, Render-hosted.

Run:  python oura_mcp.py          (streamable-http on HOST:PORT, path /mcp)
Env:  OURA_CLIENT_ID, OURA_CLIENT_SECRET, MCP_SECRET, PUBLIC_URL, TOKEN_PATH

IMPORTANT, AND DIFFERENT FROM THE FASTTRACK LITERATURE CONNECTOR:
that server is deliberately public. Its tools take no credential because open
access is the product. This one serves one person's health record, so every
route that can reach data is shut behind MCP_SECRET. Do not copy the open
pattern across. A Render URL is guessable and gets scanned.

SDK pin: built on FastMCP (mcp 1.x), matching fasttrack-literature-mcp. mcp
2.0.0 removed mcp.server.fastmcp and killed a Render deploy there once
already; requirements.txt carries the same <2 pin for the same reason.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse

VERSION = "0.1.0"

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("oura")

# --- Configuration ---------------------------------------------------------

CLIENT_ID = os.environ.get("OURA_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("OURA_CLIENT_SECRET", "").strip()

# The shared key that gates every data route. Without it the server refuses to
# serve anything rather than falling open, because falling open here publishes
# a health record.
MCP_SECRET = os.environ.get("MCP_SECRET", "").strip()

# Public https origin of this Render service, e.g. https://oura-mcp.onrender.com
# The Oura app registration's redirect URI must be exactly PUBLIC_URL + /auth/callback
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")

# Render persistent disk mount. Anything outside the mounted disk is wiped on
# restart, which would silently log you out of Oura on every redeploy.
TOKEN_PATH = Path(os.environ.get("TOKEN_PATH", "/var/data/oura_tokens.json"))

OURA_AUTHORIZE_URL = "https://cloud.ouraring.com/oauth/authorize"
OURA_TOKEN_URL = "https://api.ouraring.com/oauth/token"
OURA_API = "https://api.ouraring.com/v2"

SCOPES = ["personal", "daily", "heartrate", "session", "spo2", "workout", "tag"]

HTTP_TIMEOUT = httpx.Timeout(20.0, connect=10.0)


def _unset(value: str) -> bool:
    """True when a setting has not really been filled in yet.

    Setup asks for the literal word "placeholder" in Render, because the Oura
    app cannot be registered until this service has a URL. A plain emptiness
    check treats "placeholder" as configured and sends the user to Oura with
    client_id=placeholder, which fails there with a message that explains
    nothing. Catch it here instead, where we can say what to do.
    """
    return not value or value.strip().lower() == "placeholder"

# --- Token storage ---------------------------------------------------------
# One file on the persistent disk. Written 0600: on a shared host the default
# umask would leave a live health credential world-readable.


def _load_tokens() -> dict | None:
    try:
        with TOKEN_PATH.open() as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as e:
        log.warning("token file unreadable: %s", type(e).__name__)
        return None


def _save_tokens(tok: dict) -> None:
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = TOKEN_PATH.with_suffix(".tmp")
    # Write-then-rename so a crash mid-write cannot leave a truncated file that
    # reads as "logged out" and forces a re-consent.
    with tmp.open("w") as fh:
        json.dump(tok, fh)
    os.chmod(tmp, 0o600)
    tmp.replace(TOKEN_PATH)


def _store_token_response(payload: dict) -> dict:
    """Normalise Oura's token response and stamp an absolute expiry."""
    expires_in = int(payload.get("expires_in", 86400))
    tok = {
        "access_token": payload.get("access_token", ""),
        "refresh_token": payload.get("refresh_token", ""),
        # 60s of slack so we refresh just before the edge, not just after.
        "expires_at": time.time() + expires_in - 60,
        "obtained_at": time.time(),
    }
    if not tok["access_token"]:
        raise RuntimeError("Oura returned no access_token")
    _save_tokens(tok)
    return tok


async def _refresh(tok: dict) -> dict:
    """Exchange the refresh token for a new access token.

    Oura may or may not rotate the refresh token on use. This could not be
    confirmed against the docs (cloud.ouraring.com is unreachable from the
    build environment), so we keep the previous refresh token when the
    response omits one rather than overwriting it with an empty string, which
    would lock the connector out permanently.
    """
    if not tok.get("refresh_token"):
        raise RuntimeError("no refresh token stored; visit /auth/start again")
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.post(
            OURA_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": tok["refresh_token"],
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
        )
        r.raise_for_status()
        payload = r.json()
    payload.setdefault("refresh_token", tok["refresh_token"])
    log.info("refreshed Oura access token")
    return _store_token_response(payload)


async def _access_token() -> str:
    tok = _load_tokens()
    if not tok:
        raise RuntimeError(
            "Not connected to Oura yet. Open the /auth/start link in a browser "
            "to grant access, then try again."
        )
    if time.time() >= tok.get("expires_at", 0):
        tok = await _refresh(tok)
    return tok["access_token"]


# --- Oura API --------------------------------------------------------------


async def _get(path: str, params: dict) -> dict:
    """One authenticated GET against the Oura v2 API, retrying once after a
    401 in case the access token expired between our check and the call."""
    token = await _access_token()
    url = f"{OURA_API}{path}"
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.get(url, params=params,
                             headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 401:
            tok = _load_tokens()
            if tok:
                tok = await _refresh(tok)
                r = await client.get(
                    url, params=params,
                    headers={"Authorization": f"Bearer {tok['access_token']}"})
        r.raise_for_status()
        return r.json()


def _err(e: Exception) -> dict:
    """Plain-language errors for the person reading them, technical detail to
    the logs. A wrong answer about your own health data is worse than a clear
    statement that something is broken, so nothing here guesses."""
    log.warning("tool error: %s", repr(e))
    if isinstance(e, httpx.TimeoutException):
        return {"error": "Oura timed out. This is usually transient, try again "
                         "in a few seconds."}
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code == 401:
            return {"error": "Oura rejected the stored login. Open the "
                             "/auth/start link in a browser to reconnect."}
        if code == 403:
            return {"error": "Oura returned 403. This normally means the ring "
                             "membership has lapsed, since API access requires "
                             "an active subscription."}
        if code == 429:
            return {"error": "Oura rate limit reached. Wait a minute and retry."}
        return {"error": f"Oura returned HTTP {code}."}
    if isinstance(e, RuntimeError):
        return {"error": str(e)}
    return {"error": f"Unexpected problem: {type(e).__name__}."}


def _dates(start_date: str | None, end_date: str | None, default_days: int = 7):
    """Default to the last N complete days when no range is given."""
    if end_date is None:
        end_date = date.today().isoformat()
    if start_date is None:
        start = date.fromisoformat(end_date) - timedelta(days=default_days - 1)
        start_date = start.isoformat()
    return start_date, end_date


class _Fields:
    """Reads nested values and remembers which ones were absent.

    The Oura v2 field names could not be verified while this was written, so
    every tool reports what it could not find instead of returning a tidy row
    of nulls. A null reads as "you slept badly and we have no numbers"; an
    explicit miss reads as "the API changed", which is the truth and is
    actionable. See fields_checked in every response.
    """

    def __init__(self) -> None:
        self.missing: set[str] = set()

    def pick(self, obj: Any, *path: str, default: Any = None) -> Any:
        cur = obj
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                self.missing.add(".".join(path))
                return default
            cur = cur[key]
        if cur is None:
            self.missing.add(".".join(path))
        return cur

    def report(self) -> dict:
        if not self.missing:
            return {"fields_checked": "all expected fields present"}
        return {
            "fields_checked": "SOME EXPECTED FIELDS WERE MISSING",
            "missing_fields": sorted(self.missing),
            "note": ("Oura's field names may have changed since this connector "
                     "was written. Compare the names above against "
                     "https://api.ouraring.com/v2/docs and update oura_mcp.py. "
                     "Do not read a missing field as a low reading."),
        }


def _mean(values: list[float]) -> float | None:
    vals = [v for v in values if isinstance(v, (int, float))]
    return round(sum(vals) / len(vals), 2) if vals else None


# --- MCP server ------------------------------------------------------------

_INSTRUCTIONS = (
    "Read-only access to one person's own Oura Ring record: sleep, readiness, "
    "overnight breathing and SpO2, and workouts. Report the numbers returned "
    "and their trend. Do not offer diagnosis. If a response reports missing "
    "fields, say so plainly rather than treating a missing value as a low "
    "reading. Overnight SpO2 and breathing data require a Gen 3 ring or Ring 4 "
    "and are reported per night, not continuously."
)

mcp = FastMCP(
    "oura",
    instructions=_INSTRUCTIONS,
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8000")),
    stateless_http=True,
)


@mcp.tool()
async def check_connection() -> dict:
    """Confirm the connector can reach Oura and that the stored login works.
    Run this first if any other tool reports an error. Returns the ring
    generation and subscription state, which decide whether SpO2 and breathing
    data are available at all."""
    try:
        data = await _get("/usercollection/personal_info", {})
        f = _Fields()
        out = {
            "connected": True,
            "email": f.pick(data, "email"),
            "age": f.pick(data, "age"),
        }
        # Ring generation decides whether SpO2 and breathing data exist at all,
        # so surface it here rather than leaving get_breathing to return an
        # empty list that looks like a fault.
        try:
            rings = await _get("/usercollection/ring_configuration", {})
            out["rings"] = [{
                "hardware_type": r.get("hardware_type"),
                "design": r.get("design"),
                "colour": r.get("color"),
                "set_up_at": r.get("set_up_at"),
            } for r in rings.get("data", [])]
        except Exception:  # noqa: BLE001 - diagnostics must not fail the check
            out["rings"] = "could not read ring configuration"
        out.update(f.report())
        out["raw_personal_info"] = data
        return out
    except Exception as e:
        return _err(e)


@mcp.tool()
async def get_sleep(start_date: str | None = None,
                    end_date: str | None = None) -> dict:
    """Nightly sleep for a date range: total sleep, efficiency, stage split and
    the Oura sleep score. Dates are YYYY-MM-DD. Defaults to the last 7 days."""
    start_date, end_date = _dates(start_date, end_date)
    try:
        detail = await _get("/usercollection/sleep",
                            {"start_date": start_date, "end_date": end_date})
        summary = await _get("/usercollection/daily_sleep",
                             {"start_date": start_date, "end_date": end_date})
        f = _Fields()
        scores = {f.pick(d, "day"): f.pick(d, "score")
                  for d in summary.get("data", [])}
        nights = []
        for d in detail.get("data", []):
            day = f.pick(d, "day")
            nights.append({
                "day": day,
                "sleep_score": scores.get(day),
                "total_sleep_hours": _hours(f.pick(d, "total_sleep_duration")),
                "deep_sleep_hours": _hours(f.pick(d, "deep_sleep_duration")),
                "rem_sleep_hours": _hours(f.pick(d, "rem_sleep_duration")),
                "awake_hours": _hours(f.pick(d, "awake_time")),
                "efficiency_pct": f.pick(d, "efficiency"),
                "average_heart_rate": f.pick(d, "average_heart_rate"),
                "average_hrv": f.pick(d, "average_hrv"),
                "respiratory_rate": f.pick(d, "average_breath"),
            })
        return {"start_date": start_date, "end_date": end_date,
                "nights": nights, "night_count": len(nights), **f.report()}
    except Exception as e:
        return _err(e)


@mcp.tool()
async def get_readiness(start_date: str | None = None,
                        end_date: str | None = None) -> dict:
    """Daily readiness score and its contributors, including resting heart
    rate, HRV balance and body temperature deviation. Dates are YYYY-MM-DD.
    Defaults to the last 7 days."""
    start_date, end_date = _dates(start_date, end_date)
    try:
        data = await _get("/usercollection/daily_readiness",
                          {"start_date": start_date, "end_date": end_date})
        f = _Fields()
        days = [{
            "day": f.pick(d, "day"),
            "readiness_score": f.pick(d, "score"),
            "temperature_deviation_c": f.pick(d, "temperature_deviation"),
            "resting_heart_rate": f.pick(d, "contributors", "resting_heart_rate"),
            "hrv_balance": f.pick(d, "contributors", "hrv_balance"),
            "body_temperature": f.pick(d, "contributors", "body_temperature"),
            "recovery_index": f.pick(d, "contributors", "recovery_index"),
        } for d in data.get("data", [])]
        return {"start_date": start_date, "end_date": end_date,
                "days": days, "day_count": len(days), **f.report()}
    except Exception as e:
        return _err(e)


@mcp.tool()
async def get_breathing(start_date: str | None = None,
                        end_date: str | None = None) -> dict:
    """Overnight blood oxygen and breathing: average SpO2 percentage, the
    breathing disturbance index, and respiratory rate per night. Requires a
    Gen 3 ring or Ring 4. Dates are YYYY-MM-DD. Defaults to the last 7 days.

    The breathing disturbance index is Oura's own measure of how disrupted
    breathing was overnight. It is not a clinical apnoea score and does not
    diagnose anything."""
    start_date, end_date = _dates(start_date, end_date)
    try:
        spo2 = await _get("/usercollection/daily_spo2",
                          {"start_date": start_date, "end_date": end_date})
        sleep = await _get("/usercollection/sleep",
                           {"start_date": start_date, "end_date": end_date})
        f = _Fields()
        breath = {f.pick(d, "day"): f.pick(d, "average_breath")
                  for d in sleep.get("data", [])}
        nights = []
        for d in spo2.get("data", []):
            day = f.pick(d, "day")
            nights.append({
                "day": day,
                "spo2_avg_pct": f.pick(d, "spo2_percentage", "average"),
                "breathing_disturbance_index": f.pick(
                    d, "breathing_disturbance_index"),
                "respiratory_rate": breath.get(day),
            })
        out = {"start_date": start_date, "end_date": end_date,
               "nights": nights, "night_count": len(nights), **f.report()}
        if not nights:
            out["note"] = ("No SpO2 records returned for this range. Overnight "
                           "SpO2 needs a Gen 3 ring or Ring 4, and Oura does "
                           "not record it every night.")
        return out
    except Exception as e:
        return _err(e)


@mcp.tool()
async def get_workouts(start_date: str | None = None,
                       end_date: str | None = None) -> dict:
    """Logged workouts for a date range, with activity type, intensity,
    duration and calories. Dates are YYYY-MM-DD. Defaults to the last 7 days."""
    start_date, end_date = _dates(start_date, end_date)
    try:
        data = await _get("/usercollection/workout",
                          {"start_date": start_date, "end_date": end_date})
        f = _Fields()
        out = []
        for d in data.get("data", []):
            start, end = f.pick(d, "start_datetime"), f.pick(d, "end_datetime")
            out.append({
                "day": f.pick(d, "day"),
                "activity": f.pick(d, "activity"),
                "intensity": f.pick(d, "intensity"),
                "calories": f.pick(d, "calories"),
                "distance_m": f.pick(d, "distance"),
                "duration_minutes": _minutes_between(start, end),
            })
        return {"start_date": start_date, "end_date": end_date,
                "workouts": out, "workout_count": len(out), **f.report()}
    except Exception as e:
        return _err(e)


@mcp.tool()
async def compare_periods(period_a_start: str, period_a_end: str,
                          period_b_start: str, period_b_end: str,
                          label_a: str = "Period A",
                          label_b: str = "Period B") -> dict:
    """Compare two date ranges across sleep, readiness and overnight breathing,
    for questions like whether nights away differ from a home baseline. Dates
    are YYYY-MM-DD.

    Returns the averages for each period and the difference between them.
    Ranges of only a few nights move a lot on normal variation alone, so treat
    small differences as noise and say so."""
    try:
        a = await _period_means(period_a_start, period_a_end)
        b = await _period_means(period_b_start, period_b_end)
        metrics = ["sleep_score", "total_sleep_hours", "efficiency_pct",
                   "respiratory_rate", "spo2_avg_pct",
                   "breathing_disturbance_index", "readiness_score"]
        diff = {}
        for m in metrics:
            av, bv = a["means"].get(m), b["means"].get(m)
            diff[m] = (round(bv - av, 2)
                       if isinstance(av, (int, float)) and isinstance(bv, (int, float))
                       else None)
        thin = [p["label"] for p in
                ({"label": label_a, **a}, {"label": label_b, **b})
                if p["nights"] < 3]
        out = {
            label_a: {"range": f"{period_a_start} to {period_a_end}",
                      "nights": a["nights"], **a["means"]},
            label_b: {"range": f"{period_b_start} to {period_b_end}",
                      "nights": b["nights"], **b["means"]},
            "difference_b_minus_a": diff,
            "fields_checked": a["fields_checked"] if a["missing"] or b["missing"]
                              else "all expected fields present",
        }
        if thin:
            out["caution"] = (f"Fewer than 3 nights in: {', '.join(thin)}. "
                              "Too few to separate a real change from ordinary "
                              "night-to-night variation.")
        return out
    except Exception as e:
        return _err(e)


def _hours(seconds: Any) -> float | None:
    return round(seconds / 3600, 2) if isinstance(seconds, (int, float)) else None


def _minutes_between(start: Any, end: Any) -> float | None:
    try:
        a = datetime.fromisoformat(str(start))
        b = datetime.fromisoformat(str(end))
        return round((b - a).total_seconds() / 60, 1)
    except (TypeError, ValueError):
        return None


async def _period_means(start: str, end: str) -> dict:
    """Averages for one date range, shared by compare_periods."""
    f = _Fields()
    sleep = await _get("/usercollection/sleep",
                       {"start_date": start, "end_date": end})
    daily = await _get("/usercollection/daily_sleep",
                       {"start_date": start, "end_date": end})
    ready = await _get("/usercollection/daily_readiness",
                       {"start_date": start, "end_date": end})
    spo2 = await _get("/usercollection/daily_spo2",
                      {"start_date": start, "end_date": end})
    nights = sleep.get("data", [])
    means = {
        "sleep_score": _mean([f.pick(d, "score") for d in daily.get("data", [])]),
        "total_sleep_hours": _mean(
            [_hours(f.pick(d, "total_sleep_duration")) for d in nights]),
        "efficiency_pct": _mean([f.pick(d, "efficiency") for d in nights]),
        "respiratory_rate": _mean([f.pick(d, "average_breath") for d in nights]),
        "readiness_score": _mean(
            [f.pick(d, "score") for d in ready.get("data", [])]),
        "spo2_avg_pct": _mean([f.pick(d, "spo2_percentage", "average")
                               for d in spo2.get("data", [])]),
        "breathing_disturbance_index": _mean(
            [f.pick(d, "breathing_disturbance_index")
             for d in spo2.get("data", [])]),
    }
    return {"means": means, "nights": len(nights),
            "missing": f.missing, **f.report()}


# --- Routes ----------------------------------------------------------------
# /health is open (liveness only, no data). Everything else is shut.


@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> PlainTextResponse:
    """Liveness check. Deliberately reveals nothing beyond version and whether
    a login is stored, so it is safe to leave open for Render's health probe."""
    state = "connected" if _load_tokens() else "not-connected"
    return PlainTextResponse(f"ok {VERSION} {state}")


@mcp.custom_route("/", methods=["GET"])
async def root(request: Request) -> HTMLResponse:
    return HTMLResponse(
        "<h1>Oura connector</h1><p>Private endpoint. Nothing to see here.</p>",
        status_code=404)


@mcp.custom_route("/auth/start", methods=["GET"])
async def auth_start(request: Request) -> Any:
    """Begin the Oura consent flow. Open this in a phone browser:

        https://<your-service>/auth/start?key=<MCP_SECRET>

    Gated by the same secret as the tools, so a stranger cannot start a flow
    against your app registration.
    """
    if not _secret_ok(request.query_params.get("key", "")):
        return PlainTextResponse("Not found", status_code=404)
    missing = [n for n, v in (("OURA_CLIENT_ID", CLIENT_ID),
                              ("OURA_CLIENT_SECRET", CLIENT_SECRET),
                              ("PUBLIC_URL", PUBLIC_URL)) if _unset(v)]
    if missing:
        return PlainTextResponse(
            "Not configured yet. Set these in the Render dashboard under "
            "Environment, replacing the placeholder values, then wait for the "
            "redeploy: " + ", ".join(missing), status_code=500)
    state = secrets.token_urlsafe(24)
    _save_state(state)
    url = f"{OURA_AUTHORIZE_URL}?" + urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": f"{PUBLIC_URL}/auth/callback",
        "scope": " ".join(SCOPES),
        "state": state,
    })
    return RedirectResponse(url)


@mcp.custom_route("/auth/callback", methods=["GET"])
async def auth_callback(request: Request) -> PlainTextResponse:
    """Where Oura sends the browser back. Exchanges the one-time code for
    tokens and writes them to the persistent disk."""
    err = request.query_params.get("error")
    if err:
        return PlainTextResponse(
            f"Oura refused the request: {err}. Check the scopes on your app "
            "registration.", status_code=400)
    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    # The state check is what stops a stranger replaying a code of their own
    # into your connector and pointing it at their account.
    if not code or not _consume_state(state):
        return PlainTextResponse(
            "Invalid or expired request. Start again from /auth/start.",
            status_code=400)
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.post(OURA_TOKEN_URL, data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": f"{PUBLIC_URL}/auth/callback",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            })
            if r.status_code >= 400:
                log.warning("token exchange failed: %s", r.status_code)
                return PlainTextResponse(
                    f"Oura rejected the token exchange (HTTP {r.status_code}). "
                    "The usual cause is a redirect URI that does not match the "
                    "registration exactly, character for character. Expected: "
                    f"{PUBLIC_URL}/auth/callback", status_code=400)
            _store_token_response(r.json())
    except Exception as e:  # noqa: BLE001
        log.warning("callback failed: %s", repr(e))
        return PlainTextResponse(f"Could not complete sign-in: "
                                 f"{type(e).__name__}", status_code=500)
    return PlainTextResponse(
        "Connected to Oura. Tokens saved. You can close this tab and ask "
        "Claude about your data.")


# --- Security --------------------------------------------------------------


def _secret_ok(presented: str) -> bool:
    """Constant-time comparison. A plain == leaks the secret one character at
    a time to anyone willing to measure response times."""
    if not MCP_SECRET or not presented:
        return False
    return secrets.compare_digest(presented, MCP_SECRET)


_STATE_PATH = TOKEN_PATH.parent / "oauth_state.json"
_STATE_TTL = 600  # ten minutes is ample for a consent screen


def _save_state(state: str) -> None:
    try:
        _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        existing = {}
        if _STATE_PATH.exists():
            existing = json.loads(_STATE_PATH.read_text())
        now = time.time()
        existing = {k: v for k, v in existing.items() if v > now}
        existing[state] = now + _STATE_TTL
        _STATE_PATH.write_text(json.dumps(existing))
    except (OSError, json.JSONDecodeError) as e:
        log.warning("could not persist oauth state: %s", type(e).__name__)


def _consume_state(state: str) -> bool:
    """One-time use: a state is valid once, then destroyed."""
    if not state:
        return False
    try:
        states = json.loads(_STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    expiry = states.pop(state, None)
    try:
        _STATE_PATH.write_text(json.dumps(states))
    except OSError:
        pass
    return bool(expiry and expiry > time.time())


class RequireSecret:
    """Pure ASGI gate in front of everything except the open routes.

    Deliberately answers 404 rather than 401. A 401 confirms to a scanner that
    something worth attacking lives here; a 404 says only that the URL is
    uninteresting. Applied outermost so nothing reaches the MCP transport
    unauthenticated.
    """

    OPEN_PATHS = {"/health", "/", "/auth/start", "/auth/callback"}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in self.OPEN_PATHS:
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        presented = headers.get("authorization", "")
        if presented.lower().startswith("bearer "):
            presented = presented[7:].strip()
        if not _secret_ok(presented):
            log.warning("rejected unauthenticated request to %s", path)
            await send({"type": "http.response.start", "status": 404,
                        "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": b"Not found"})
            return
        await self.app(scope, receive, send)



# --- Wider data coverage ---------------------------------------------------
# Everything Oura v2 exposes, not just the sleep and breathing subset. The
# endpoint names below come from the published v2 collection list. Field names
# inside each are still unverified, which is exactly why _Fields reports
# misses rather than returning silent nulls.

ENDPOINTS = {
    "daily_activity": "steps, calories and the activity score",
    "daily_sleep": "nightly sleep score and contributors",
    "daily_readiness": "readiness score and contributors",
    "daily_spo2": "overnight blood oxygen and breathing disturbance",
    "daily_stress": "daytime stress and recovery minutes",
    "daily_resilience": "longer-term resilience classification",
    "daily_cardiovascular_age": "cardiovascular age estimate",
    "vO2_max": "estimated VO2 max",
    "sleep": "detailed per-night sleep periods",
    "sleep_time": "recommended bedtime windows",
    "workout": "workouts, auto-detected and logged",
    "session": "guided sessions: meditation, breathwork, rest",
    "tag": "legacy user-entered tags",
    "enhanced_tag": "structured user-entered tags",
    "rest_mode_period": "rest mode periods",
    "ring_configuration": "ring hardware, including generation",
    "personal_info": "account profile",
    "heartrate": "continuous heart rate samples (uses datetimes)",
}

# heartrate is bounded by timestamps, every other collection by dates.
_DATETIME_ENDPOINTS = {"heartrate"}
# These carry no date range at all; sending one returns a 400.
_UNDATED_ENDPOINTS = {"personal_info", "ring_configuration"}


@mcp.tool()
async def list_available_data() -> dict:
    """List every Oura data collection this connector can reach, with a short
    description of each. Use this to find out what is available before calling
    get_raw for something without a dedicated tool."""
    return {
        "endpoints": ENDPOINTS,
        "note": ("Collections with a dedicated tool return tidied fields. "
                 "Anything else is reachable through get_raw, which returns "
                 "Oura's response unmodified."),
    }


@mcp.tool()
async def get_raw(endpoint: str, start_date: str | None = None,
                  end_date: str | None = None) -> dict:
    """Fetch any Oura v2 collection and return its response unchanged.

    The escape hatch: use it for data with no dedicated tool, or to see the
    real field names when a tidied tool reports missing fields. Call
    list_available_data for valid endpoint names. Dates are YYYY-MM-DD and are
    ignored for collections that do not accept a range."""
    name = endpoint.strip().strip("/").split("/")[-1]
    if name not in ENDPOINTS:
        return {"error": f"Unknown endpoint '{endpoint}'.",
                "valid_endpoints": sorted(ENDPOINTS)}
    try:
        if name in _UNDATED_ENDPOINTS:
            params: dict = {}
        elif name in _DATETIME_ENDPOINTS:
            s, e = _dates(start_date, end_date)
            params = {"start_datetime": f"{s}T00:00:00+00:00",
                      "end_datetime": f"{e}T23:59:59+00:00"}
        else:
            s, e = _dates(start_date, end_date)
            params = {"start_date": s, "end_date": e}
        data = await _get(f"/usercollection/{name}", params)
        records = data.get("data", data) if isinstance(data, dict) else data
        return {"endpoint": name, "params": params,
                "record_count": len(records) if isinstance(records, list) else 1,
                "data": data}
    except Exception as e:
        return _err(e)


@mcp.tool()
async def get_activity(start_date: str | None = None,
                       end_date: str | None = None) -> dict:
    """Daily activity: steps, calories burned, active and sedentary time, and
    the activity score. Dates are YYYY-MM-DD. Defaults to the last 7 days."""
    start_date, end_date = _dates(start_date, end_date)
    try:
        data = await _get("/usercollection/daily_activity",
                          {"start_date": start_date, "end_date": end_date})
        f = _Fields()
        days = [{
            "day": f.pick(d, "day"),
            "activity_score": f.pick(d, "score"),
            "steps": f.pick(d, "steps"),
            "active_calories": f.pick(d, "active_calories"),
            "total_calories": f.pick(d, "total_calories"),
            "sedentary_minutes": f.pick(d, "sedentary_time"),
            "high_activity_minutes": f.pick(d, "high_activity_time"),
        } for d in data.get("data", [])]
        return {"start_date": start_date, "end_date": end_date,
                "days": days, "day_count": len(days), **f.report()}
    except Exception as e:
        return _err(e)


@mcp.tool()
async def get_stress(start_date: str | None = None,
                     end_date: str | None = None) -> dict:
    """Daytime stress and longer-term resilience: minutes spent in stress
    versus recovery, and Oura's resilience classification. Dates are
    YYYY-MM-DD. Defaults to the last 7 days."""
    start_date, end_date = _dates(start_date, end_date)
    try:
        stress = await _get("/usercollection/daily_stress",
                            {"start_date": start_date, "end_date": end_date})
        f = _Fields()
        days = [{
            "day": f.pick(d, "day"),
            "stress_high_minutes": f.pick(d, "stress_high"),
            "recovery_high_minutes": f.pick(d, "recovery_high"),
            "day_summary": f.pick(d, "day_summary"),
        } for d in stress.get("data", [])]
        out = {"start_date": start_date, "end_date": end_date,
               "days": days, "day_count": len(days)}
        try:
            res = await _get("/usercollection/daily_resilience",
                             {"start_date": start_date, "end_date": end_date})
            out["resilience"] = [{
                "day": f.pick(d, "day"),
                "level": f.pick(d, "level"),
                "contributors": f.pick(d, "contributors"),
            } for d in res.get("data", [])]
        except httpx.HTTPStatusError:
            # Resilience is not available on every account or ring generation.
            out["resilience"] = "not available on this account"
        out.update(f.report())
        return out
    except Exception as e:
        return _err(e)


@mcp.tool()
async def get_cardiovascular(start_date: str | None = None,
                             end_date: str | None = None) -> dict:
    """Cardiovascular age estimate and VO2 max. These update infrequently, so
    a wide date range usually returns only a handful of records. Dates are
    YYYY-MM-DD. Defaults to the last 30 days."""
    start_date, end_date = _dates(start_date, end_date, default_days=30)
    out: dict = {"start_date": start_date, "end_date": end_date}
    f = _Fields()
    for key, path in (("cardiovascular_age", "daily_cardiovascular_age"),
                      ("vo2_max", "vO2_max")):
        try:
            data = await _get(f"/usercollection/{path}",
                              {"start_date": start_date, "end_date": end_date})
            out[key] = data.get("data", [])
        except httpx.HTTPStatusError as e:
            out[key] = f"not available (HTTP {e.response.status_code})"
        except Exception as e:
            return _err(e)
    out.update(f.report())
    return out


@mcp.tool()
async def get_heart_rate(start_date: str | None = None,
                         end_date: str | None = None) -> dict:
    """Continuous heart rate samples. This returns a lot of points, so it
    summarises by default: count, range, mean, and the split between awake and
    sleep samples. Use get_raw('heartrate', ...) for every individual sample.
    Dates are YYYY-MM-DD. Defaults to the last 2 days, because the volume is
    high."""
    start_date, end_date = _dates(start_date, end_date, default_days=2)
    try:
        data = await _get("/usercollection/heartrate", {
            "start_datetime": f"{start_date}T00:00:00+00:00",
            "end_datetime": f"{end_date}T23:59:59+00:00"})
        f = _Fields()
        samples = data.get("data", [])
        bpms = [f.pick(s, "bpm") for s in samples]
        bpms = [b for b in bpms if isinstance(b, (int, float))]
        by_source: dict[str, list] = {}
        for s in samples:
            by_source.setdefault(str(s.get("source", "unknown")), []).append(
                s.get("bpm"))
        return {
            "start_date": start_date, "end_date": end_date,
            "sample_count": len(samples),
            "bpm_min": min(bpms) if bpms else None,
            "bpm_max": max(bpms) if bpms else None,
            "bpm_mean": _mean(bpms),
            "by_source": {k: {"count": len(v), "mean": _mean(v)}
                          for k, v in by_source.items()},
            **f.report(),
        }
    except Exception as e:
        return _err(e)


@mcp.tool()
async def get_sessions(start_date: str | None = None,
                       end_date: str | None = None) -> dict:
    """Guided sessions (meditation, breathwork, rest) and any tags you entered
    yourself, which is where notes like 'travelling' or 'alcohol' live. Useful
    for explaining why a particular night differs. Dates are YYYY-MM-DD.
    Defaults to the last 7 days."""
    start_date, end_date = _dates(start_date, end_date)
    out: dict = {"start_date": start_date, "end_date": end_date}
    for key, path in (("sessions", "session"), ("tags", "enhanced_tag"),
                      ("legacy_tags", "tag")):
        try:
            data = await _get(f"/usercollection/{path}",
                              {"start_date": start_date, "end_date": end_date})
            out[key] = data.get("data", [])
        except httpx.HTTPStatusError as e:
            out[key] = f"not available (HTTP {e.response.status_code})"
        except Exception as e:
            return _err(e)
    return out


if __name__ == "__main__":
    import uvicorn

    # Refuse to start rather than serve a health record with no lock on the
    # door. A missing secret is a deployment mistake, and the safe response to
    # it is to stay down and be noticed, not to come up open.
    if not MCP_SECRET:
        raise SystemExit(
            "MCP_SECRET is not set. Refusing to start: without it the tools "
            "would be readable by anyone who finds this URL. Set MCP_SECRET "
            "in the Render dashboard to a long random string."
        )
    if len(MCP_SECRET) < 24:
        raise SystemExit(
            f"MCP_SECRET is only {len(MCP_SECRET)} characters. Use at least 24 "
            "random characters, this is the sole protection on your health data."
        )
    if not PUBLIC_URL.startswith("https://"):
        log.warning("PUBLIC_URL is not https, the OAuth redirect will fail")

    app = RequireSecret(mcp.streamable_http_app())
    uvicorn.run(app, host=mcp.settings.host, port=mcp.settings.port)
