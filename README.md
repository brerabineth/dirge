# dirge

```
                          ,   ,$$s.
                       ,$$$s,s$$$$$s.
   _____             .s$$$$$$$$$$$$$'
  |     | .-----. .--| |----.---.-.-----.
  |  |  ||  _  ||  _  ||   _|  _  |  _  |
  |____  ||_____||_____||__| |_____|_____|
  |:  1  |                        the mail autopsy
  |::.. . |
  `-------'
```

A bell rung for the dead letter. `dirge` reads suspicious email so you
don't have to open it: one static binary, no network, no dependencies,
one exit code a pipeline can gate on.

Most mail analysis lives behind a gateway or inside a SIEM. The actual
question an analyst asks at 2 a.m. is smaller: *someone forwarded me
this .eml — what is it trying to do?* `dirge` answers that offline, in
milliseconds, and refuses to guess about things it cannot see.

## why now

AI-assisted phishing stopped being a novelty in late 2025: reported
samples with AI fingerprints jumped from 4% in November to 56% in
December and stayed high through 2026, and measured click-through on
AI-written lures is roughly 4x that of human-written ones. The lures
are polished, personalized and cheap. Triage tooling did not get
faster to match. `dirge` is the fast, local, scriptable part of that
answer — the full methodology notes are in `doc/methodology.md`.

## what it reads

- RFC 5322 headers, RFC 2047 encoded words, MIME trees — nested
  `multipart/*`, `message/rfc822`, RFC 2231 extended parameters,
  base64 and quoted-printable bodies
- archives, by central-directory walk (no unzip needed): docx/xlsx/
  pptx containers get inspected for VBA projects and `.pyc` payloads
  the same way as plain zip attachments
- PDF byte structure, RTF object streams, attached HTML

## what it checks

| family | examples |
|---|---|
| headers | SPF/DKIM/DMARC results, Reply-To / Return-Path / Message-ID domain mismatches, display-name brand impersonation, Date-vs-Received skew, direct injection (no Received chain) |
| urls | brand tokens outside real domains, typosquat distance, punycode, raw-IP hosts, shorteners, open-redirect parameters, credential-shaped paths, `data:` HTML documents decoded and re-scanned, tracking pixels |
| attachments | exec masquerade as documents, double extensions, bidi-override filename spoofs, office macros, PDF `/Launch`/`/OpenAction`/`/JavaScript`, RTF objects, HTML smuggling |
| content | agent-directed instructions (mail written for the machine that reads it), urgency / credential / scare / crypto / callback phrasing, invisible unicode, whitespace inflation, hidden bait text |
| templates | AI-assisted fingerprints: generic HTML comments, emoji CTAs, rounded buttons, highlight boxes |

Findings carry weights; the sum maps to a verdict and an exit code.
Certain findings force hostile regardless of the sum — bidi filename
spoofs, credential forms in embedded documents, masqueraded
executables, invisible text — plus two combinations (macros + brand
impersonation, scanner-padding + agent bait). `dirge rules` prints the
full catalog with weights.

## build

Any OCaml >= 4.14 with the stock `str` and `unix` libraries:

```
make
make test        # 109 internal checks
make fixtures    # deterministic demo mail in fixtures/
```

No opam, no dune, no external packages — the compiler and libc are
the whole story.

## use

```
$ dirge scan incident.eml                 # terminal card, exit code
$ dirge scan samples/ --json > triage.json
$ dirge scan samples/ --md > report.md
$ cat fwd.eml | dirge scan -              # pipelines
$ dirge scan inbox/ --min-score 25        # render only what matters
$ dirge explain                           # methodology + citations
```

Exit codes: `0` clean, `1` watch, `3` suspicious, `10` hostile,
`2` usage error. A multi-file scan exits with the worst band.

Deterministic by construction: no wall clock, no randomness, no
locale — the same input produces byte-identical JSON, which makes
diff-able triage history possible with nothing but `cmp`.

## verify

Releases ship a linux-x64 binary and a `SHA256SUMS`. The selftest
runs inside the binary: `./dirge selftest`. For a visual smoke test,
`dirge forge fixtures/` writes six deterministic sample mails — a
legitimate newsletter, a spoofed bank lure with a masqueraded
executable, an embedded-document credential form, an AI-templated
notice, a macro container, and a scanner-padding attack — then:

```
$ dirge scan fixtures/
$ echo $?
```

## limitations

- offline by principle: no DNS lookups, no header reputation, no
  url sandboxing — structural evidence only
- S/MIME encrypted parts are flagged as opaque, not decrypted
- zip walking names central-directory entries; it does not inflate
  streams (no zlib), so compressed payload bytes are not scanned —
  entry names plus the outer format carry the verdicts
- the AI-template heuristics measure likelihood, not intent; they
  are documented fingerprints from published 2026 measurement work,
  not a classifier

## license

BSD-2-Clause. See `LICENSE`.
