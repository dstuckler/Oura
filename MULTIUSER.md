# Multi-user connector: proven, and what is left

A design was tested end to end on 21 August 2026 and works: **one hosted
connector, each user authenticating with their own Oura account, no health
data stored by the operator.**

This file records what was actually verified, what was not, and what stands
between the proof and something other people can use. `oura_multiuser.py` implements it; the throwaway that
established it has been removed rather than left to drift.

## The problem it solves

Phone users cannot self-host: an MCP server on a phone is not a thing, so a
remote endpoint is required, so somebody hosts it. Self-deploy answers the
data question but costs each user a Render service and an Oura app
registration. Hosting it for people answers the friction question by making
the operator the custodian of other people's health records.

The OAuth broker avoids both. The operator hosts, and the token stays with
the user.

## What was verified

Against the live service, with Claude on iOS as the client:

- Claude discovered the server needed auth, registered itself, and opened the
  consent flow unprompted. Nothing was pasted or configured by hand.
- Consent happened on Oura, against the user's own account.
- `whoami` returned that user's own profile, read with their own token.
- The server's only state was in memory: registered clients and in-flight
  codes. No token or health record was written anywhere.

The user added a URL and logged in. That was the whole setup.

## What was NOT verified

- **A second user.** The flow was exercised once, by the same person who owns
  the Oura app registration. A different account takes the same code path,
  but that path has not actually been run.
- **Anything beyond 10 users.** Oura caps an unapproved app there. The gate
  is real and belongs to Oura, not to this code.
- **Restart behaviour under load.** Registrations are in memory, so a restart
  drops them. Observed directly: state reset to zero on redeploy.

## The claim to make, and the one not to

"We never store your Oura login or your health data" is true: tokens live in
the user's own client and health data is read, returned and discarded.

"We store nothing" is now slightly too strong. One file is written: the list
of registered OAuth clients, holding no credential of the user's and no
health data, without which every user is signed out on each restart.

"Your data never touches our servers" is **false** and must not be written
anywhere. Tokens and health data pass through memory on every call. The
operator is transiently in the path. Logging must therefore never capture
request or response bodies, and a privacy policy has to describe the transit
honestly.

## Remaining work

1. ~~Port the 14 tools.~~ Done. `oura_multiuser.py` registers the same
   function objects `oura_mcp.py` exposes, with the token source swapped
   through the `TOKEN_PROVIDER` hook. There is no second copy of any tool
   body. Verified: two different callers in one process each get their own
   token forwarded, and a caller with no session gets an error rather than
   falling back to the operator's stored token.
2. ~~Persist client registrations.~~ Done, and it was the cause of the
   daily re-login rather than token expiry. The token endpoint authenticates
   the client with `get_client()` before it will refresh anything, so a
   restart that lost the registration had refreshes rejected as
   `Invalid client_id` and the user was asked to sign in again. Their refresh
   token had been valid throughout. Registrations now live on a Render disk
   at `/var/data`, written 0600 through a temp file and rename. Verified to
   survive a restart and to contain no access or refresh token.
3. ~~Make Claude refresh expired logins.~~ Done. The connector went dead
   about a month after login and stayed dead: every tool returned Oura's
   401, and the Render logs for the preceding 30 days held no request to
   `/token` at all. Claude only refreshes when the server answers 401, and
   the server accepted any bearer because it had no expiry to check, so the
   stale token was waved through, Oura refused it inside the tool, and that
   came back as an ordinary tool error with HTTP 200. The token Claude holds
   is now `v1.<expiry>.<oura token>`: an expired one is answered 401, Claude
   refreshes through `/token`, and Oura only ever sees the inner token.
   Still nothing is stored. A bare token from before this change is also
   answered 401, so existing users move over through one refresh. Verified
   locally against a simulated Oura on mcp 1.28 and 1.30: login, expiry,
   refresh, refused refresh. Not verified: that Claude's refresh after the
   401 succeeds against the live server. That shows on first use after
   deploy.
4. **Oura app approval**, to pass 10 users. Start early; it is someone
   else's timeline.
5. **Rename the app.** The consent screen currently reads "Oura Personal
   MCP", which is wrong for a shared tool. Both Render services use this
   one Oura app registration.
6. **Privacy policy**, per the wording above.

## Why the single-user server still exists

`oura_mcp.py` remains the working personal connector: one token on a
persistent disk, one user, a shared secret on the door. It is simpler, has no
transit question at all, and is the right shape for one person. The broker is
for giving the tool to others, not for replacing it.
