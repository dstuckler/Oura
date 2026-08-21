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
import re
import secrets
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode

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

# The first seven are confirmed working: they are exactly the seven items
# Oura's consent screen offered, and every collection behind them returns
# data.
#
# Both SpO2 spellings are requested deliberately. The published spec and docs
# say "spo2Daily"; other sources say "spo2", and the checkbox in the developer
# portal is labelled plain "SpO2". Requesting spo2Daily alone produced a
# consent screen with no SpO2 item at all and no error, which is what an
# unrecognised scope looks like: Oura drops what it does not know rather than
# rejecting the request. That same silence makes sending both safe, since the
# wrong one can only be ignored, and it settles the question in one consent
# instead of two.
#
# If the consent screen gains an SpO2 item, the surviving spelling is the real
# one and the other can be dropped.
SCOPES = ["email", "personal", "daily", "heartrate", "workout", "tag",
          "session", "spo2Daily", "spo2"]

HTTP_TIMEOUT = httpx.Timeout(20.0, connect=10.0)

# Pagination guard. Oura allows 5000 requests per 5 minutes; this bounds a
# single tool call well inside that even on a multi-year range.
MAX_PAGES = 50


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


# Where the Oura token comes from. None means the disk store below, which is
# the single-user server's own behaviour and the default.
#
# oura_multiuser.py sets this to read the token off the incoming request
# instead, so one hosted server can serve many people without holding anyone's
# credentials. Every tool in this file then works unchanged under either
# model: the tools never ask where the token came from, and there is no second
# copy of them to drift out of step with this one.
TOKEN_PROVIDER = None


async def _access_token() -> str:
    if TOKEN_PROVIDER is not None:
        return await TOKEN_PROVIDER()
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
    merged: dict | None = None
    page_params = dict(params)
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        for page in range(MAX_PAGES):
            r = await client.get(url, params=page_params,
                                 headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 401:
                tok = _load_tokens()
                if tok:
                    tok = await _refresh(tok)
                    token = tok["access_token"]
                    r = await client.get(
                        url, params=page_params,
                        headers={"Authorization": f"Bearer {token}"})
            r.raise_for_status()
            body = r.json()
            if merged is None:
                merged = body
            elif isinstance(body.get("data"), list):
                merged["data"].extend(body["data"])
            # Oura paginates multi-document responses. Stopping at the first
            # page silently truncates a wide range, which reads as "you have
            # no data for those days" rather than "there is more".
            nxt = body.get("next_token") if isinstance(body, dict) else None
            if not nxt or not isinstance(merged.get("data"), list):
                break
            page_params = {**params, "next_token": nxt}
        else:
            log.warning("hit MAX_PAGES on %s; response is truncated", path)
            if isinstance(merged, dict):
                merged["truncated"] = True
    merged.pop("next_token", None)
    return merged


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
            # Oura answers 401, not the documented 403, when a collection is
            # outside the granted scopes. Telling the user only to reconnect
            # sends them round the same loop: re-consent regrants exactly the
            # scopes the app registration allows, so if the tick is missing
            # there, nothing changes. Name both causes and how to tell them
            # apart.
            return {"error": (
                "Oura returned 401 for this collection. If other tools still "
                "work, the stored login is fine and this is a missing scope: "
                "the app registration does not grant this data type. Check "
                "the scopes on the app at developer.ouraring.com, tick the "
                "missing one, then open /auth/start again to re-consent. "
                "spo2Daily covers SpO2 and breathing. If every tool returns "
                "this, the login itself has gone and re-consenting alone "
                "fixes it.")}
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
    """Reads nested values, separating a renamed field from an empty one.

    Two different things look alike in a tidied row of nulls, and only one is
    a fault:

    absent  - the key is not in the record at all. Across a whole response
              that means the API has been renamed and the tool is reading a
              field that no longer exists. Actionable, and worth shouting
              about.
    null    - the key is there and its value is null. Oura did not compute
              that metric for that night, which is ordinary: a night with no
              breathing disturbance index sits beside nights that have one.

    Reporting a null as drift is not harmless. A warning that fires on normal
    data teaches the reader to ignore it, and it is the same warning that
    would carry a real rename. So a key seen with a value somewhere in the
    response is never reported as missing, however many nulls it also has.
    """

    def __init__(self) -> None:
        self.absent: set[str] = set()
        self.nulls: set[str] = set()
        self.seen: set[str] = set()

    def pick(self, obj: Any, *path: str, default: Any = None) -> Any:
        name = ".".join(path)
        cur = obj
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                self.absent.add(name)
                return default
            cur = cur[key]
        if cur is None:
            self.nulls.add(name)
        else:
            self.seen.add(name)
        return cur

    def report(self) -> dict:
        # A field that produced a value anywhere is present; the nulls are
        # gaps in the data, not evidence of a rename.
        drifted = sorted(self.absent - self.seen)
        # Any field that was ever null, or absent on some records while
        # present on others, is a gap worth naming. Subtracting `seen` here
        # would erase exactly the interesting case: a metric Oura computes on
        # most nights and skips on one.
        gaps = sorted(self.nulls | (self.absent & self.seen))
        out: dict = {}
        if drifted:
            out["fields_checked"] = "SOME EXPECTED FIELDS WERE MISSING"
            out["missing_fields"] = drifted
            out["note"] = (
                "These field names were not present on any record, which "
                "usually means Oura renamed them. Compare against "
                "https://api.ouraring.com/v2/docs and update oura_mcp.py. "
                "Do not read a missing field as a low reading.")
        else:
            out["fields_checked"] = "all expected fields present"
        if gaps:
            out["fields_null_on_some_records"] = gaps
            out["gap_note"] = ("Present in the response but not computed for "
                               "every record. A normal gap in the data, not a "
                               "renamed field and not a low reading.")
        return out


def _mean(values: list[float]) -> float | None:
    vals = [v for v in values if isinstance(v, (int, float))]
    return round(sum(vals) / len(vals), 2) if vals else None


def _main_sleep(records: list[dict]) -> tuple[dict[str, dict], list[dict]]:
    """Split sleep periods into one main night per day, and everything else.

    The sleep collection returns a record per sleep *period*, not per night.
    A day with a nap or a brief re-settle carries two or three, typed
    "long_sleep" for the real night and "sleep" for the rest. Treating them
    alike does three bad things: the same date appears twice, a day-keyed
    lookup silently keeps whichever record came last, and an average over
    periods weights a 30-second fragment the same as an eight-hour night.

    Short fragments also carry average_breath: null, so counting them makes
    the missing-field report cry drift when nothing has drifted.

    Prefer the long_sleep period; where a day has none, fall back to its
    longest period so a nap-only day still reports something.
    """
    def rank(r: dict) -> tuple:
        return (r.get("type") == "long_sleep",
                r.get("total_sleep_duration") or 0)

    best: dict[str, dict] = {}
    for r in records:
        day = r.get("day")
        if day is None:
            continue
        if day not in best or rank(r) > rank(best[day]):
            best[day] = r
    chosen = {id(r) for r in best.values()}
    others = [r for r in records if id(r) not in chosen]
    return best, others


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
        # Contributors say *why* a score landed where it did: which of deep,
        # rem, latency, restfulness or timing pulled it down.
        contribs = {d.get("day"): d.get("contributors")
                    for d in summary.get("data", [])}
        main, naps = _main_sleep(detail.get("data", []))
        nights = []
        for day in sorted(main):
            d = main[day]
            nights.append({
                "day": day,
                "sleep_type": d.get("type"),
                "sleep_score": scores.get(day),
                "total_sleep_hours": _hours(f.pick(d, "total_sleep_duration")),
                "deep_sleep_hours": _hours(f.pick(d, "deep_sleep_duration")),
                "rem_sleep_hours": _hours(f.pick(d, "rem_sleep_duration")),
                "light_sleep_hours": _hours(f.pick(d, "light_sleep_duration")),
                "awake_hours": _hours(f.pick(d, "awake_time")),
                "time_in_bed_hours": _hours(f.pick(d, "time_in_bed")),
                "efficiency_pct": f.pick(d, "efficiency"),
                "latency_minutes": _mins(f.pick(d, "latency")),
                "restless_periods": f.pick(d, "restless_periods"),
                "average_heart_rate": f.pick(d, "average_heart_rate"),
                "lowest_heart_rate": f.pick(d, "lowest_heart_rate"),
                "average_hrv": f.pick(d, "average_hrv"),
                "respiratory_rate": f.pick(d, "average_breath"),
                "bedtime_start": d.get("bedtime_start"),
                "bedtime_end": d.get("bedtime_end"),
                "score_contributors": contribs.get(day),
            })
        out = {"start_date": start_date, "end_date": end_date,
               "nights": nights, "night_count": len(nights), **f.report()}
        if naps:
            # Reported separately rather than dropped: a nap is real data, it
            # just is not a night and must not be averaged as one.
            out["naps_and_fragments"] = [
                {"day": n.get("day"), "type": n.get("type"),
                 "hours": _hours(n.get("total_sleep_duration"))} for n in naps]
        return out
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
            "temperature_trend_deviation": f.pick(d, "temperature_trend_deviation"),
            "resting_heart_rate": f.pick(d, "contributors", "resting_heart_rate"),
            "hrv_balance": f.pick(d, "contributors", "hrv_balance"),
            "body_temperature": f.pick(d, "contributors", "body_temperature"),
            "recovery_index": f.pick(d, "contributors", "recovery_index"),
            "activity_balance": f.pick(d, "contributors", "activity_balance"),
            "sleep_balance": f.pick(d, "contributors", "sleep_balance"),
            "sleep_regularity": f.pick(d, "contributors", "sleep_regularity"),
            "previous_night": f.pick(d, "contributors", "previous_night"),
            "previous_day_activity": f.pick(d, "contributors", "previous_day_activity"),
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
        # Respiratory rate lives on the sleep collection, SpO2 and the
        # disturbance index on daily_spo2, and the two are granted by
        # different scopes. Fetch them independently so losing one does not
        # discard the other: an account without the SpO2 scope still has a
        # real breaths-per-minute figure for every night, and returning only
        # an error would hide data the user does have.
        sleep = await _get("/usercollection/sleep",
                           {"start_date": start_date, "end_date": end_date})
        spo2: dict = {"data": []}
        spo2_error = None
        try:
            spo2 = await _get("/usercollection/daily_spo2",
                              {"start_date": start_date, "end_date": end_date})
        except httpx.HTTPStatusError as e:
            spo2_error = _err(e)["error"]
        f = _Fields()
        # Main night only. Keying every period by day let a late fragment,
        # which carries no average_breath, overwrite the real night's value
        # and report the respiratory rate as missing.
        main, _ = _main_sleep(sleep.get("data", []))
        breath = {day: f.pick(d, "average_breath") for day, d in main.items()}
        by_day = {f.pick(d, "day"): d for d in spo2.get("data", [])}
        # Drive the rows off the nights actually slept, not off the SpO2
        # response, so the table still has a row per night when SpO2 is absent.
        nights = []
        for day in sorted(set(breath) | set(by_day)):
            d = by_day.get(day)
            nights.append({
                "day": day,
                "spo2_avg_pct": (f.pick(d, "spo2_percentage", "average")
                                 if d else None),
                "breathing_disturbance_index": (
                    f.pick(d, "breathing_disturbance_index") if d else None),
                "respiratory_rate": breath.get(day),
            })
        out = {"start_date": start_date, "end_date": end_date,
               "nights": nights, "night_count": len(nights), **f.report()}
        if spo2_error:
            out["spo2_unavailable"] = spo2_error
            out["what_you_still_have"] = (
                "respiratory_rate is from the sleep collection and is "
                "unaffected. spo2_avg_pct and breathing_disturbance_index are "
                "null because that collection was refused, not because the "
                "readings were low.")
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


def _mins(seconds: Any) -> float | None:
    """Oura reports durations in seconds unless stated otherwise. Naming a
    seconds value "minutes" turns 31200 seconds of sitting into 31200 minutes,
    which is 21 days."""
    return round(seconds / 60, 1) if isinstance(seconds, (int, float)) else None


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
    # One night per day. Averaging raw periods let a 30-second fragment, with
    # an efficiency near zero and no respiratory rate, count as heavily as a
    # full night: over a short comparison window that alone can invent a
    # difference between two periods.
    main, _ = _main_sleep(sleep.get("data", []))
    nights = list(main.values())
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
        # Fall back to ?key= in the URL. Claude's mobile "add custom connector"
        # form offers a URL and OAuth credentials, with nowhere to set a static
        # header, so a header-only gate cannot be configured from a phone at
        # all. The query string is the only channel that surface gives us.
        # Weaker, since URLs reach logs and browser history, but the
        # alternative is either no connector or no lock.
        if not _secret_ok(presented):
            qs = parse_qs(scope.get("query_string", b"").decode("latin-1"))
            presented = (qs.get("key") or [""])[0]
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
    "ring_battery_level": "current ring battery",
    "personal_info": "account profile",
    "heartrate": "continuous heart rate samples (uses datetimes)",
}

# heartrate is bounded by timestamps, every other collection by dates.
_DATETIME_ENDPOINTS = {"heartrate"}
# These carry no date range at all; sending one returns a 400.
_UNDATED_ENDPOINTS = {"personal_info", "ring_configuration",
                      "ring_battery_level"}


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
                  end_date: str | None = None, sandbox: bool = False) -> dict:
    """Fetch any Oura v2 collection and return its response unchanged.

    The escape hatch: use it for data with no dedicated tool, or to see the
    real field names when a tidied tool reports missing fields. Call
    list_available_data for valid endpoint names. Dates are YYYY-MM-DD and are
    ignored for collections that do not accept a range.

    sandbox=True hits Oura's sample-data namespace instead of the real record.
    Useful as a diagnostic: if a collection fails on real data but works in
    the sandbox, the request and parsing are sound and the fault is in what
    the token is permitted to read. The values are Oura's fixtures, not
    yours, so never present them as the user's own readings."""
    name = endpoint.strip().strip("/").split("/")[-1]
    if name not in ENDPOINTS:
        return {"error": f"Unknown endpoint '{endpoint}'.",
                "valid_endpoints": sorted(ENDPOINTS)}
    # personal_info has no sandbox counterpart in the spec.
    if sandbox and name == "personal_info":
        return {"error": "personal_info has no sandbox route."}
    prefix = "/sandbox/usercollection" if sandbox else "/usercollection"
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
        data = await _get(f"{prefix}/{name}", params)
        records = data.get("data", data) if isinstance(data, dict) else data
        out = {"endpoint": name, "params": params,
               "record_count": len(records) if isinstance(records, list) else 1,
               "data": data}
        if sandbox:
            out["source"] = ("Oura sandbox fixtures, NOT this user's data. "
                             "Do not report these as real readings.")
        return out
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
            "target_calories": f.pick(d, "target_calories"),
            "walking_equivalent_m": f.pick(d, "equivalent_walking_distance"),
            "average_met_minutes": f.pick(d, "average_met_minutes"),
            # Every *_time field is seconds in the API.
            "sedentary_minutes": _mins(f.pick(d, "sedentary_time")),
            "resting_minutes": _mins(f.pick(d, "resting_time")),
            "low_activity_minutes": _mins(f.pick(d, "low_activity_time")),
            "medium_activity_minutes": _mins(f.pick(d, "medium_activity_time")),
            "high_activity_minutes": _mins(f.pick(d, "high_activity_time")),
            "non_wear_minutes": _mins(f.pick(d, "non_wear_time")),
            "inactivity_alerts": f.pick(d, "inactivity_alerts"),
            "contributors": f.pick(d, "contributors"),
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
            rows = data.get("data", [])
            if key == "cardiovascular_age":
                # vascular_age is the headline number: an age estimate, so a
                # value below your real age is the good direction.
                out[key] = [{"day": f.pick(r, "day"),
                             "vascular_age": f.pick(r, "vascular_age"),
                             "pulse_wave_velocity": f.pick(
                                 r, "pulse_wave_velocity")} for r in rows]
            else:
                out[key] = rows
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


def _utc_offset(timestamp: Any) -> str | None:
    """The trailing +HH:MM or -HH:MM on an ISO 8601 timestamp."""
    if not isinstance(timestamp, str):
        return None
    m = re.search(r"([+-]\d{2}:\d{2})$", timestamp)
    return m.group(1) if m else None


def _offset_hours(offset: str) -> float:
    sign = -1 if offset.startswith("-") else 1
    hh, mm = offset[1:].split(":")
    return sign * (int(hh) + int(mm) / 60)


def _nth_weekday(year: int, month: int, weekday: int, n: int) -> date:
    """The nth given weekday of a month; n=-1 means the last one."""
    days = [date(year, month, d)
            for d in range(1, (date(year, month % 12 + 1, 1)
                               - timedelta(days=1)).day + 1)]
    matches = [d for d in days if d.weekday() == weekday]
    return matches[n if n < 0 else n - 1]


def _dst_boundaries(year: int) -> set[date]:
    """Clock-change Sundays for the EU and US in a given year.

    Both are covered because either can appear in one record: a European home
    offset shifts on the EU dates, a US one on the US dates, and someone who
    moves between them sees both.
    """
    return {
        _nth_weekday(year, 3, 6, -1),    # EU spring, last Sunday in March
        _nth_weekday(year, 10, 6, -1),   # EU autumn, last Sunday in October
        _nth_weekday(year, 3, 6, 2),     # US spring, second Sunday in March
        _nth_weekday(year, 11, 6, 1),    # US autumn, first Sunday in November
    }


def _is_clock_change(day: str, prev_off: str, new_off: str) -> bool:
    """True when an offset change looks like daylight saving, not travel.

    Two conditions together, because either alone gives false positives: the
    shift is exactly one hour, and it lands within a day of a clock-change
    Sunday. A real flight of exactly one hour on that precise weekend would be
    misread, which is a rarer and much smaller error than calling a whole
    winter a trip abroad.
    """
    try:
        d = date.fromisoformat(day)
    except (TypeError, ValueError):
        return False
    if abs(_offset_hours(new_off) - _offset_hours(prev_off)) != 1.0:
        return False
    return any(abs((d - b).days) <= 1 for b in _dst_boundaries(d.year))


@mcp.tool()
async def find_travel_periods(start_date: str | None = None,
                              end_date: str | None = None,
                              min_nights: int = 1) -> dict:
    """Work out which nights were spent away, from timezone changes alone.

    Use this before compare_periods when the question is about travel, so the
    date ranges come from the record rather than from memory.

    Oura stores no location: the ring has no GPS and the API exposes no
    latitude, city or country. What it does store is the UTC offset on each
    night's bedtime, so crossing a timezone is visible even though the place
    is not. The offset seen on the most nights is treated as home, and each
    run of nights at a different offset is reported as a trip.

    This misses any travel that does not change timezone, so a trip within
    one country looks identical to being at home, and a night that merely
    crosses a daylight-saving change will show up as a spurious one-night
    trip. Treat the output as a prompt to confirm, not as a record of where
    you were. Dates are YYYY-MM-DD, default the last 180 days."""
    start_date, end_date = _dates(start_date, end_date, default_days=180)
    try:
        sleep = await _get("/usercollection/sleep",
                           {"start_date": start_date, "end_date": end_date})
        main, _ = _main_sleep(sleep.get("data", []))
        nights = [(day, _utc_offset(main[day].get("bedtime_start")))
                  for day in sorted(main)]
        nights = [(d, o) for d, o in nights if o]
        if not nights:
            return {"error": "No sleep records with a timezone in this range."}

        # Label each night with a zone rather than a raw offset. A daylight
        # saving change shifts the offset without moving anyone, so the label
        # carries across it. Without this, one European winter reads as a
        # 36-night trip and can out-vote the real home for the count below.
        zoned: list[tuple[str, str, str]] = []   # day, zone label, offset
        zone = nights[0][1]
        prev_off = nights[0][1]
        clock_changes = []
        for day, off in nights:
            if off != prev_off:
                if _is_clock_change(day, prev_off, off):
                    clock_changes.append(
                        {"day": day, "from": prev_off, "to": off})
                else:
                    zone = off
                prev_off = off
            zoned.append((day, zone, off))

        counts: dict[str, int] = {}
        for _, z, _o in zoned:
            counts[z] = counts.get(z, 0) + 1
        home = max(counts, key=lambda k: counts[k])

        # Collapse consecutive nights sharing a zone into one run.
        runs = []
        for day, z, off in zoned:
            if runs and runs[-1]["zone"] == z:
                runs[-1]["end_day"] = day
                runs[-1]["nights"] += 1
                runs[-1]["offsets"].add(off)
            else:
                runs.append({"start_day": day, "end_day": day, "zone": z,
                             "offsets": {off}, "nights": 1})
        for r in runs:
            offs = sorted(r.pop("offsets"))
            # A run spanning a clock change legitimately holds two offsets.
            r["utc_offset"] = "/".join(offs) if len(offs) > 1 else offs[0]

        # Compare zones, not printed offsets: a run spanning a clock change
        # carries a combined "+01:00/+02:00" label that is not a number.
        trips = [{**r,
                  "hours_from_home": round(
                      _offset_hours(r["zone"]) - _offset_hours(home), 1),
                  "direction": ("east" if _offset_hours(r["zone"])
                                > _offset_hours(home) else "west")}
                 for r in runs
                 if r["zone"] != home and r["nights"] >= min_nights]

        out = {
            "range": f"{start_date} to {end_date}",
            "nights_analysed": len(nights),
            "home_offset": home,
            "home_nights": counts[home],
            "trips": trips,
            "trip_count": len(trips),
            "nights_per_zone": counts,
        }
        if clock_changes:
            # Reported so the reader can see they were considered and
            # discounted, rather than wondering why an offset change is absent
            # from the trip list.
            out["daylight_saving_changes"] = clock_changes
            out["note"] = (
                "Offset changes on a clock-change weekend were treated as "
                "daylight saving, not travel. A one-hour shift landing exactly "
                "on that Sunday is assumed to be the clock, not a flight.")
        thin = [t for t in trips if t["nights"] < 3]
        if thin:
            out["caution"] = (
                "Trips of fewer than 3 nights are listed but are too short to "
                "compare against a baseline: night-to-night variation alone "
                "will usually exceed any real difference. "
                + ", ".join(f"{t['start_day']} ({t['nights']} night"
                            f"{'s' if t['nights'] != 1 else ''})" for t in thin))
        if not trips:
            out["note"] = ("Every night in this range shares one timezone. "
                           "That means no travel across timezones, not "
                           "necessarily no travel.")
        return out
    except Exception as e:
        return _err(e)


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
