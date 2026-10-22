# methodology

How `dirge` decides what is suspicious, and where the evidence comes
from. Every rule is deterministic: same input, same verdict, same
bytes out.

## threat basis

The 2026 measurement literature gives three anchors:

- Hoxhunt's phishing trend analysis tracked reported samples carrying
  AI-assistance fingerprints rising from 4% (November 2025) to 56%
  (December 2025), holding near 40% into 2026. Their methodology also
  catalogues the structural fingerprints `dirge` implements: generic
  HTML comments and section labels ("Main Content", "Click to Call"),
  emoji call-to-action buttons, highlight boxes with a thick left
  border, rounded-corner buttons, uniformly polished grammar.
- Independent click-rate measurement puts AI-written lures near 54%
  click-through against 12% for human-written messages.
- Trail of Bits' skill-distribution study (June 2026) demonstrated
  that scanner pipelines truncate oversized inputs; a payload hidden
  after ~100k newlines passes under the inspection window. `dirge`
  takes the opposite stance: it never truncates, and a whitespace
  run of 5,000+ newlines is itself a finding (b.inflation), because
  padding exists to defeat readers — mechanical or human.

## scoring

Each rule has a fixed weight (see `dirge rules`). Weights sum to a
score; the score maps to a band:

| band | score | exit |
|---|---|---|
| clean | 0-9 | 0 |
| watch | 10-24 | 1 |
| suspicious | 25-59 | 3 |
| hostile | 60+ | 10 |

Forcing rules override the sum. These exist because some evidence is
unambiguous regardless of everything else:

- `a.rtl_override` — a bidi control character inside an attachment
  filename exists to make "exe" display as "pdf". No benign mail
  contains one.
- `u.credential_form` / `a.att_credential_form` — a password input
  inside an embedded or attached HTML document.
- `a.masquerade_doc` — an executable wearing a document extension
  chain.
- `b.unicode_smuggle` — invisible characters (bidi controls, Unicode
  tags, zero-width runs) in body text or the subject.

Two combinations force hostile because each half alone is ambiguous:

- macros in an office container + brand impersonation anywhere
- whitespace inflation + instructions aimed at an automated reader

Mailing-list traffic (List-Id / List-Unsubscribe present) suppresses
the three rewritten-in-transit domain checks, because lists
legitimately rewrite Return-Path and Message-ID.

## design stances

- Offline only. Structural evidence the file itself carries: header
  relationships, MIME structure, byte markers, phrasing. No DNS, no
  reputation feeds, no sandbox.
- Nothing is truncated. Bodies, headers and archives are read whole;
  oversize input is reported, not trimmed.
- Determinism is a feature: no wall clock, no randomness, no map
  iteration order. Reports diff cleanly across time.
- String evidence shown to a human is masked for credential shapes
  and defanged for URLs; invisible characters are stripped from
  display but counted in findings.

## fixture correspondence

The six forged samples in `fixtures/` pin the bands: the newsletter
must stay clean, the AI-templated notice must land in watch, and the
spoofed bank lure, the embedded credential form, the macro container
and the padding attack must all reach hostile with their distinct
rule sets. The selftest asserts every one of these verdicts.
