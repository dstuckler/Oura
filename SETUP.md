# Oura MCP Connector — Setup

Everything here can be done from a phone browser. There is no terminal step and
no computer required.

Hosted on Render, like the FastTrack literature connector, but **locked down**.
That one is deliberately public. This one serves a personal health record, so
every route that can reach data requires a secret key.

---

## What is different from the FastTrack connector

| | FastTrack literature | This one |
|---|---|---|
| Who can call the tools | Anyone with the URL, by design | Only you, via a secret key |
| If the secret is missing | n/a | Server refuses to start |
| Plan | Free tier is fine | Paid starter, needs a persistent disk |
| Login stored | None needed | Oura token on the disk |

The paid plan is not optional here. Free Render instances have no persistent
disk, so the Oura login is wiped on every restart and sleep, and you would be
re-consenting from your phone constantly.

---

## Where this stands

The Render service is already created and live. You do not need to deploy it.

| | |
|---|---|
| Service | `oura-mcp` |
| URL | `https://oura-mcp-2jaj.onrender.com` |
| Repo / branch | `dstuckler/Oura`, `claude/oura-mcp-setup-p4oahb` |
| Plan | Starter, 1 GB disk at `/var/data`, Ohio |
| Auto-deploy | On. Pushing to the branch redeploys. |

`MCP_SECRET` was generated and set in Render. Read it from the dashboard when
you need it: Environment tab, reveal `MCP_SECRET`. It is not written down
anywhere else, by design.

Remaining steps are the ones that need your Oura login, so they are yours.

### 1. Register the Oura app

Sign in at `cloud.ouraring.com`, then go straight to:

```
https://cloud.ouraring.com/oauth/applications
```

The developer area is not linked from the Oura app's normal navigation, so
that direct address is the way in. Create an application there.

**Redirect URI, exactly this:**

```
https://oura-mcp-2jaj.onrender.com/auth/callback
```

No trailing slash, https not http. A mismatch here is the most common failure
in the whole process.

**Scopes:** tick all eight, exactly as spelled here:

`email` · `personal` · `daily` · `heartrate` · `workout` · `tag` · `session` · `spo2Daily`

Note **`spo2Daily`**, not `spo2`. The original handoff said `spo2`, which is
not a real scope name. Getting this wrong does not produce an error: consent
succeeds and `daily_spo2` simply returns nothing, which looks like an
unsupported ring or a renamed field rather than a missing permission.

**Website / privacy policy:** required, any valid URL works for a personal app.

You get a Client ID and a Client Secret.

### 2. Put them into Render

Dashboard, `oura-mcp`, Environment. Replace the two `placeholder` values:

- `OURA_CLIENT_ID`
- `OURA_CLIENT_SECRET`

Save. **Then use Manual Deploy to restart the service.** Saving an environment
variable does not always trigger a redeploy on its own, and the running
process only reads these at startup, so a saved-but-not-restarted service
still behaves as though nothing changed.

Check it took effect: open `/auth/start?key=<MCP_SECRET>`. If it still says
"Not configured yet", the restart has not happened.

### 3. Connect to Oura

In a phone browser, open:

```
https://oura-mcp-2jaj.onrender.com/auth/start?key=<MCP_SECRET>
```

Log in, consent, and Oura returns you to a page saying
**"Connected to Oura. Tokens saved."**

Confirm: `https://oura-mcp-2jaj.onrender.com/health` should change from
`not-connected` to `connected`.

### 4. Add the connector to Claude

Settings, Connectors, Add custom connector.

- **URL:** `https://oura-mcp-2jaj.onrender.com/mcp`
- **Header:** `Authorization` = `Bearer <MCP_SECRET>`

Without the header the server answers 404 and Claude reports it cannot find
anything. That is the lock working, not a fault.

### 5. Test with real data

Thirteen tools should appear, covering everything Oura v2 exposes:

| Tool | Data |
|---|---|
| `check_connection` | account, and which ring you have |
| `get_sleep` | nightly sleep, stages, efficiency |
| `get_readiness` | readiness score and contributors |
| `get_breathing` | SpO2, breathing disturbance, respiratory rate |
| `get_activity` | steps, calories, active and sedentary time |
| `get_stress` | daytime stress, recovery, resilience |
| `get_cardiovascular` | cardiovascular age, VO2 max |
| `get_heart_rate` | continuous heart rate, summarised |
| `get_workouts` | workouts |
| `get_sessions` | meditation and breathwork, plus your own tags |
| `compare_periods` | two date ranges side by side |
| `list_available_data` | what else is reachable |
| `get_raw` | any collection, unmodified |

`get_raw` is the escape hatch. If a tidied tool reports missing fields, call
`get_raw` on the same collection to see the real field names Oura is
returning, then the code can be corrected against reality.

Run `check_connection` first, then:

```
get_breathing(start_date="2026-08-14", end_date="2026-08-20")
```

**Read the `fields_checked` line.** `all expected fields present` means the
numbers are real. `SOME EXPECTED FIELDS WERE MISSING` lists which ones, and
means Oura renamed something: a code fix, not a health finding. A missing
field must never be read as a low reading.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Claude cannot see the connector | The `Authorization: Bearer` header is missing or wrong. The server answers 404 on purpose rather than confirming it exists. |
| Service will not start, logs say `MCP_SECRET is not set` | Working as designed. It refuses to come up unprotected. Set it in Render. |
| `Oura rejected the token exchange (HTTP 400)` | Redirect URI mismatch. Compare the registration against `PUBLIC_URL` + `/auth/callback` character by character. |
| `403` from any tool | Oura membership lapsed. API access needs an active subscription. |
| `get_breathing` returns no nights | SpO2 needs a Gen 3 ring or Ring 4, and Oura does not record it every night. |
| Logged out after a redeploy | The disk is not mounted, or `TOKEN_PATH` is not on it. Both should point at `/var/data`. |

---

## What was tested before deploying, and what was not

**Tested here, against the real MCP 1.x SDK:**

- All six tools register.
- The server refuses to start with no `MCP_SECRET`, and with one under 24 characters.
- `/mcp` returns 404 with no credential and with a wrong credential, and 200 with the right one.
- `/auth/start` returns 404 without the key, and redirects to Oura with all seven scopes with it.
- Sleep, breathing and comparison parsing, against mock Oura responses.
- Field-drift detection: when a field name is changed, the tool names the missing field instead of returning a silent null.

**Not tested, and cannot be from a cloud session:**

- Any call against the live Oura API. Oura's domains are blocked by the network
  policy here, which is why step 6 is the real test.
- The exact v2 field names. The docs are on a blocked domain. This is why the
  drift detection exists.
- Whether Oura rotates the refresh token on use. The code keeps the old one if
  a new one is not sent, which is safe either way.

---

## SDK version

Pinned to `mcp>=1.28,<2`, matching `fasttrack-literature-mcp`. mcp 2.0.0 removed
`mcp.server.fastmcp` and killed a Render deploy on that repo once already. Both
repos migrate together, deliberately, never through a surprise resolver upgrade.

Note that the original handoff described `oura_mcp.py` as built on the 2.0 API
(`from mcp.server import MCPServer`). This rewrite is on 1.x instead, for the
reason above.

---

## Context

Built to compare travel nights against a home baseline; `compare_periods` exists
for that. The clinical question has moved ahead of this tooling and is with a
doctor. This is longitudinal tracking, not diagnostics, and carries no time
pressure. The tools report numbers and trends and do not interpret them
medically.
