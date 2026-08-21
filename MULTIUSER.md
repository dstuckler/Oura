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
3. **Oura app approval**, to pass 10 users. Start early; it is someone
   else's timeline.
4. **Rename the app.** The consent screen currently reads "Oura Personal
   MCP", which is wrong for a shared tool.
5. **Privacy policy**, per the wording above.

## Why the single-user server still exists

`oura_mcp.py` remains the working personal connector: one token on a
persistent disk, one user, a shared secret on the door. It is simpler, has no
transit question at all, and is the right shape for one person. The broker is
for giving the tool to others, not for replacing it.
