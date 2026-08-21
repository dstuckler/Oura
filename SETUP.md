# Oura MCP Server — Setup

**Read this on the machine you'll actually run it from. That must be your Mac.**

This replaces the original handoff notes. Some claims in those notes were
checked against reality on 2026-08-21; the results are recorded below.

---

## Before you start: this cannot be done from a phone or a cloud session

Three things must happen on one physical computer — the same one, at the same time:

1. `oura_mcp.py` has to exist on it.
2. The OAuth login step sends your browser back to `http://localhost:8080/callback`.
   `localhost` means "this same computer." The browser and the running script must
   therefore be on the same machine.
3. An MCP server over stdio is a program launched by the Claude app on that machine.

An iPhone can't satisfy any of these. A cloud session can't satisfy 1 or 2, and its
network is blocked from reaching Oura besides (verified: connections to
`api.ouraring.com` and `cloud.ouraring.com` both fail outright from a cloud container).

Use the Claude Code desktop app or the `claude` CLI in Terminal on your Mac.

---

## Verified facts (checked 2026-08-21, not recalled from memory)

| Claim | Status |
|---|---|
| MCP Python SDK is on v2.0 | **Confirmed** — 2.0.0 is the current release |
| `from mcp.server import MCPServer` | **Confirmed** — imports correctly in 2.0.0 |
| host/port are `run()` kwargs, not `server.settings.host` | **Confirmed** — real signature is `run(transport='stdio'\|'sse'\|'streamable-http', **kwargs)` |
| Oura deprecated Personal Access Tokens in Dec 2025 | **Confirmed** — new PATs cannot be created; OAuth 2.0 only for new integrations |
| Oura v2 field names for SpO2 / breathing | **NOT verified** — the docs are on a domain unreachable from the cloud session. Still an open risk at the final test step. |

Build against the installed SDK, not against v1-era tutorials.

---

## Repository state

- `.gitignore` — **done, committed, pushed.** Verified by creating decoy files and
  confirming `git check-ignore` matches each one. It covers:
  - `.oura_tokens.json` and any `*oura_tokens*.json` variant
  - `.env`, `client_secret*`, `credentials.json`
  - `*.csv` (health data exported by the legacy `oura_sync.py`)
  - standard Python / virtualenv / editor artefacts
- Everything else — **not yet in the repo.** Still in `~/Downloads` on the Mac.

Because `.gitignore` landed first, the credential trap is already shut. A token file
dropped into this folder cannot be staged by accident.

---

## Steps, corrected

### 1. Get the files in

From Terminal on your Mac, in the cloned repo folder:

```
git pull
cp ~/Downloads/oura_mcp.py ~/Downloads/README.md ~/Downloads/requirements.txt .
cp ~/Downloads/LICENSE ~/Downloads/render.yaml .
```

Do **not** copy `gitignore.txt` — a verified `.gitignore` is already committed.
Skip `oura_sync.py` unless you want the old CSV script kept for reference.

Then confirm nothing sensitive is about to be staged:

```
git status
git add -A --dry-run
```

Read that dry-run output. If anything resembling a token, secret or `.env` appears,
stop and fix `.gitignore` before committing.

### 2. Virtual environment, then dependencies

A virtual environment is a private folder of Python packages belonging to just this
project. Without one, `pip install` changes Python system-wide, so two projects
wanting different versions of the same package break each other. It also means you
can delete one folder to undo everything. Use one.

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Your prompt will show `(.venv)` once it's active. Re-run the `source` line in any new
Terminal window before running the server.

### 3. Register the Oura OAuth app

At `cloud.ouraring.com`, in the developer/application area:

- **Redirect URI:** `http://localhost:8080/callback` — exactly, character for character.
  A trailing slash or `https` will break step 4.
- **Scopes:** `personal`, `daily`, `heartrate`, `session`, `spo2`, `workout`, `tag`
- **Website / privacy policy:** required fields, but any valid URL is fine for a
  personal app.

You'll receive a **Client ID** and **Client Secret**.

**Where these go:** in the MCP config file in step 5, which lives outside this repo.
Never paste them into a file inside this folder, into a chat, or into a commit.

### 4. Authorize

```
python3 oura_mcp.py auth
```

Expected: a browser opens, you consent, tokens are written to `~/.oura_tokens.json`.

This is the step most likely to fail. Read the actual error rather than guessing:

- **`redirect_uri_mismatch`** — the registered URI differs from what the script sends.
  Compare them character by character.
- **`invalid_scope`** — a scope in the request wasn't ticked at registration.
- **`403`** — Oura membership lapsed. API access requires an active membership.
- **`Address already in use`** — something else holds port 8080. Find it with
  `lsof -i :8080`, then either quit that program or change both the script's port
  and the registered redirect URI to match.

### 5. Connect to Claude Code

stdio only — local, nothing exposed to the internet:

```json
{
  "mcpServers": {
    "oura": {
      "command": "python3",
      "args": ["/absolute/path/to/oura_mcp.py", "stdio"],
      "env": {
        "OURA_CLIENT_ID": "...",
        "OURA_CLIENT_SECRET": "..."
      }
    }
  }
}
```

Use the absolute path — run `pwd` in the repo folder to get it. If you used a
virtual environment, point `command` at `.venv/bin/python3` inside the project
rather than the bare `python3`, or the server won't find its dependencies.

### 6. Verify against real data

Confirm five tools appear: `get_sleep`, `get_readiness`, `get_breathing`,
`get_workouts`, `compare_periods`.

Then the actual test — nothing in this project has ever touched the live API:

```
get_breathing(start_date="...", end_date="...")
```

Expect real numbers for `spo2_avg_pct`, `breathing_disturbance_index`,
`respiratory_rate`.

If those come back null or missing, the field names in the code have probably drifted
from the current API. This is the one risk that could not be checked in advance.
Compare against `https://api.ouraring.com/v2/docs` and correct the code. SpO2 and
breathing data require a Gen 3 ring or Ring 4.

---

## Deliberately not doing

- **Render / remote deployment.** Only needed for mobile access, and it means putting
  authentication in front of a public endpoint serving personal health data.
- **Publishing publicly.** The decision was: publish the *code* so others self-deploy,
  never run a shared service.

---

## Context

Built to compare travel nights against a personal baseline — `compare_periods` exists
for that. The clinical question has since moved ahead of this tooling and is being
handled with a doctor. This is longitudinal tracking, not diagnostics, and carries no
time pressure.
