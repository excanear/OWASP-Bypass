"""Miscellaneous category solvers (5 of 6 — web3WalletChallenge needs a real
funded Sepolia-testnet wallet + paid Alchemy API key, neither of which this
environment has, and is deferred). Verified against routes/verify.ts,
lib/startup/registerWebsocketEvents.ts, and config/default.yml (fetched
2026-08-09)."""
import time
import uuid

import socketio

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/verify.ts accessControlChallenges (mounted on
# /assets/public/images/padding and, for security.txt, directly on
# /.well-known/security.txt and /security.txt): same "no referer header"
# uiBypassed trick as Phase 2's web3SandboxChallenge/adminSectionChallenge —
# a plain HTTP client naturally satisfies it. ---

@register("scoreBoardChallenge", "Miscellaneous", 1)
def solve_score_board(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/1px.png").raise_for_status()


@register("privacyPolicyChallenge", "Miscellaneous", 1)
def solve_privacy_policy(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/81px.png").raise_for_status()


@register("securityPolicyChallenge", "Miscellaneous", 2)
def solve_security_policy(ctx: SolverContext) -> None:
    ctx.client.get("/security.txt").raise_for_status()


# --- lib/startup/registerWebsocketEvents.ts: solved by emitting a
# `verifyCloseNotificationsChallenge` Socket.IO event with any array of
# more than one element — simulating "dismiss all notifications at once". ---

@register("closeNotificationsChallenge", "Miscellaneous", 1)
def solve_close_notifications(ctx: SolverContext) -> None:
    sio = socketio.SimpleClient()
    sio.connect(ctx.base_url, transports=["websocket"])
    try:
        sio.emit("verifyCloseNotificationsChallenge", [1, 2])
        time.sleep(1)
    finally:
        sio.disconnect()


# --- routes/verify.ts databaseRelatedChallenges (csafChallenge()): solved
# when a single Feedback or Complaint message contains
# config.default.yml's csafHashValue substring — same
# checkPatternInFeedbackAndComplaints pattern as Task 1's
# weirdCryptoChallenge. ---

CSAF_HASH_VALUE = "7e7ce7c65db3bf0625fcea4573d25cff41f2f7e3474f2c74334b14fc65bb4fd26af802ad17a3a03bf0eee6827a00fb8f7905f338c31b5e6ea9cb31620242e843"


@register("csafChallenge", "Miscellaneous", 3)
def solve_csaf(ctx: SolverContext) -> None:
    email = f"csaf.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/api/Complaints",
        json={"message": f"Advisory hash mismatch: {CSAF_HASH_VALUE}"},
    ).raise_for_status()
