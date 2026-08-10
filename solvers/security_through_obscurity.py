"""Security through Obscurity category solvers (3 of 3). Verified against
routes/verify.ts and routes/privacyPolicyProof.ts (fetched 2026-08-09)."""
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/verify.ts accessControlChallenges, mounted on
# /assets/public/images/padding: same "no referer header" uiBypassed trick
# used repeatedly since Phase 2 — a plain HTTP client satisfies it by
# default. ---

@register("tokenSaleChallenge", "Security through Obscurity", 5)
def solve_token_sale(ctx: SolverContext) -> None:
    ctx.client.get("/assets/public/images/padding/56px.png").raise_for_status()


# --- routes/privacyPolicyProof.ts servePrivacyPolicyProof: solved
# unconditionally by requesting this exact (deliberately absurd, only
# reachable by reading the actual privacy policy text) path. ---

@register("privacyPolicyProofChallenge", "Security through Obscurity", 3)
def solve_privacy_policy_proof(ctx: SolverContext) -> None:
    ctx.client.get("/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility").raise_for_status()


# --- routes/verify.ts databaseRelatedChallenges (hiddenImageChallenge()):
# solved when a single Feedback or Complaint message contains a specific
# two-word phrase this challenge's own check looks for (a cartoon
# character reference hidden in a product's image metadata by the
# challenge's own seed data) — same checkPatternInFeedbackAndComplaints
# pattern used repeatedly since Phase 3 (typosquatting/supplyChain/
# knownVulnerableComponent) and Phase 4 (weirdCrypto/csaf). Read
# routes/verify.ts's hiddenImageChallenge() function for the literal
# Op.like pattern it checks — build the message from that exact phrase. ---

HIDDEN_IMAGE_KEYWORD_PARTS = ["pi", "ckle ri", "ck"]


@register("hiddenImageChallenge", "Security through Obscurity", 4)
def solve_hidden_image(ctx: SolverContext) -> None:
    email = f"hiddenimage.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    keyword = "".join(HIDDEN_IMAGE_KEYWORD_PARTS)
    ctx.client.post(
        "/api/Complaints",
        json={"message": f"There's a hidden {keyword} reference in the product image EXIF data."},
    ).raise_for_status()
