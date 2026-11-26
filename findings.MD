## F1 — Any requester can read another user's booking via the API (BOLA)

Weakness: The booking API returns a booking to any signed-in user,
without checking they own it.

CWE-639 (Authorization Bypass Through User-Controlled Key)
OWASP A01:2025 Broken Access Control / API1:2023 BOLA

Location: src/routes/reservations.js
  - GET /api/reservations/:id uses requireAuth only (line ~ the /api route)
  - The page routes above it use requireOwnerOrCoordinator(db); the API does not.

Conditions: signed in; any requester; no coordinator role needed.

Evidence (signed in as maya, requester, user id 1):
  - E09  GET /api/reservations/101  -> 200, ownerId 1 (Maya's own) — normal
  - E10  GET /api/reservations/201  -> 200, ownerId 2 (Noah's), with his
         private delivery note — the leak
  - Page route /reservations/201 -> "You do not have access" — so this data
    is NOT otherwise visible to Maya.

Observed effect: a requester read another user's booking details, including a
private delivery note, by changing the id in the URL.

Possible effect (not yet tested): reading every booking by counting through ids;
the cancel API may have the same gap. To check later.

<!-- Repair: add an ownership check on the API route (same requireOwnerOrCoordinator
used by the page routes), so a requester only gets their own bookings.
Check: after the fix, E09 still returns 101; E10 returns 403/404. -->



Reproduction (anyone can repeat):
1. Start Procrastimate; sign in as maya (requester).
2. In the address bar, open /api/reservations/101  -> 200, ownerId 1 (Maya's own).
3. Open /api/reservations/201  -> 200, ownerId 2 (Noah's), with his delivery note.
4. Open the page /reservations/201 -> "You do not have access to that booking.".


## F2 — Command injection in the label preview

Weakness: The /labels/preview route builds a shell command by gluing the
raw `ref` value onto it, so typed text can run extra commands on the server.

CWE-78 (OS Command Injection)
OWASP A05:2025 Injection

Location: src/routes/labels.js, /labels/preview route.
  cp.exec('node scripts/format-reference.cjs ' + req.query.ref, ...)
  The raw req.query.ref is concatenated into a shell command. (readText is
  called but its checked value is not the one used; and it only length-checks.)

Conditions: signed in; any requester; no coordinator role needed. Windows shell.

Evidence (signed in as maya, requester):
  - E11  ref=BK-101            -> "Procrastimate reference: BK-101"  (normal)
  - E12  ref=BK-101&whoami     -> reference PLUS a second line "USER",
         the output of the injected `whoami` command.

Observed effect: input in `ref` was executed as a shell command. `whoami`
ran and returned the server account name.

Possible effect (not tested, stated as risk): any command the running user
can run could be executed. Not demonstrated, and not tested for safety reasons.

Reachability: linked from views/reservations/show.ejs (the "Reference label"
link on a booking page) using the booking's own SKU; but the route reads
req.query.ref, so a user can edit the URL to supply any value, as in E12.

<!-- Repair: do not build a shell command from input. Use cp.execFile('node',
['scripts/format-reference.cjs', ref]) so the reference is passed as a single
argument, never parsed by a shell. Also use the checked `ref`, not req.query.ref.
Check: after the fix, E12 returns the formatted reference only, with no second
line; E11 still works. -->


## F3 — Reflected XSS in the packing preview

Weakness: The /packing/preview route puts the `name` value straight into the
page's HTML without escaping, so typed HTML/script runs in the browser.

CWE-79 (Cross-site Scripting)
OWASP A05:2025 Injection

Location: src/routes/packing.js, /packing/preview route.
  res.type('html').send('<h1>Hello ' + req.query.name + '</h1>')
  Raw req.query.name concatenated into HTML; no escaping. (Contrast guides.js,
  which wraps its value in escapeHtml — that one is safe.)

Conditions: signed in; any requester.

Evidence (signed in as maya):
  - E13  name=Maya                  -> "Hello Maya" (normal)
  - E14  name=<i>Maya</i>           -> "Maya" rendered in italics; the tags were
         executed as HTML, not shown as text.
  - E15  name=<img src=x onerror="alert('XSS-20099070')">
         -> a JavaScript alert box showing XSS-20099070 ran. Script supplied in
         the URL executed in the browser.

Observed effect: attacker-supplied HTML and JavaScript executed in the page.

Possible effect (stated as risk): a crafted link could run script in another
signed-in user's browser (e.g. to steal their session or act as them). Not
tested beyond the alert.

<!-- Repair: escape the value before placing it in HTML — reuse escapeHtml(name) as
guides.js does, or render through the template engine's auto-escaping. Use the
checked value, not req.query.name.
Check: after the fix, E14 shows the literal text <i>Maya</i>; E15 shows the
literal tag and no alert; E13 still shows "Hello Maya". -->

## F4 — Path traversal in the manifest download

Weakness: The /manifests/download route builds a file path from the `f` value
with no containment check, so "../" escapes the manifests folder and returns
other files.

CWE-22 (Path Traversal)
OWASP A01:2025 Broken Access Control

Location: src/routes/manifests.js line 16:
  res.sendFile(path.resolve(manifestDir + req.query.f))
  Only check is readText (length <= 200). No allow-list, no check that the
  resolved path stays inside manifestDir.
  (Contrast guides.js, which allow-lists ['collection.txt','returns.txt'] —
  that route is safe. Same scanner rule, opposite outcome.)

Conditions: signed in; any requester.

Evidence (signed in as maya):
  - E16  f=manifest-101.txt      -> returns a normal packing sheet (inside
         the manifests folder)
  - E17  f=../procrastimate.sqlite -> downloaded the application's database
         file, which lives in the parent "data" folder, outside manifests.

Observed effect: a file outside the intended folder (the SQLite database) was
served through a route meant only for manifests.

Possible effect (stated as risk): the database holds all users, bookings and
settlement data, so this exposes the whole data store to any signed-in user.
Other files reachable by relative path may also be retrievable.

<!-- Repair: do not build the path by concatenation. Allow-list the known manifest
names (as guides.js does), or resolve the path and reject anything that does
not stay within manifestDir (e.g. check the resolved path starts with
manifestDir). Use the checked value, not req.query.f.
Check: after the fix, E16 still returns the manifest; E17 returns an error and
no file outside manifests is served. -->

