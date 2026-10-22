(* d_rules - finding catalog, weights, verdict bands, exit codes *)

type sev = SevInfo | SevLow | SevMed | SevHigh | SevCrit

type finding = {
  f_id : string;
  f_sev : sev;
  f_title : string;
  f_evidence : string list;
  f_weight : int;
}

let sev_name = function
  | SevInfo -> "info" | SevLow -> "low" | SevMed -> "medium"
  | SevHigh -> "high" | SevCrit -> "critical"

let sev_rank = function
  | SevInfo -> 0 | SevLow -> 1 | SevMed -> 2 | SevHigh -> 3 | SevCrit -> 4

(* catalog: id -> (weight, severity, title). evidence attached at scan time *)
let catalog : (string * (int * sev * string)) list = [
  (* headers *)
  ("h.no_from",              (18, SevHigh,  "no parsable From address"));
  ("h.auth_missing",         (12, SevMed,   "no SPF/DKIM/DMARC evaluation at all"));
  ("h.spf_fail",             (18, SevHigh,  "SPF fail"));
  ("h.spf_softfail",         (12, SevMed,   "SPF softfail"));
  ("h.spf_neutral",          (6,  SevLow,   "SPF neutral"));
  ("h.spf_none",             (4,  SevLow,   "SPF none (no policy)"));
  ("h.dkim_fail",            (10, SevMed,   "DKIM fail"));
  ("h.dkim_none",            (6,  SevLow,   "no DKIM evaluation"));
  ("h.dmarc_fail",           (22, SevCrit,  "DMARC fail"));
  ("h.replyto_mismatch",     (16, SevHigh,  "Reply-To domain differs from From"));
  ("h.returnpath_mismatch",  (10, SevMed,   "Return-Path domain differs from From"));
  ("h.msgid_mismatch",       (5,  SevLow,   "Message-ID domain differs from From"));
  ("h.msgid_missing",        (3,  SevLow,   "no Message-ID"));
  ("h.date_missing",         (3,  SevLow,   "no Date header"));
  ("h.date_skew",            (8,  SevMed,   "Date vs Received skew > 48h"));
  ("h.no_received",          (4,  SevLow,   "no Received chain"));
  ("h.display_spoof",        (20, SevCrit,  "display name impersonates a brand"));
  ("h.subj_unicode",         (15, SevHigh,  "invisible unicode in subject"));
  ("h.unknown_charset",      (2,  SevLow,   "exotic charset in encoded words"));
  (* body/urls *)
  ("b.unicode_smuggle",      (20, SevHigh,  "invisible unicode in body"));
  ("b.ctx_manipulation",     (12, SevMed,   "instructions aimed at an agent reading this mail"));
  ("b.urgency",              (6,  SevMed,   "urgency / deadline pressure"));
  ("b.credential_lure",      (14, SevHigh,  "credential lure phrasing"));
  ("b.threat_scare",         (10, SevMed,   "threat / legal scare phrasing"));
  ("b.crypto_lure",          (8,  SevMed,   "crypto wallet bait"));
  ("b.gift_bait",            (5,  SevLow,   "gift / prize bait"));
  ("b.callback",             (5,  SevLow,   "callback phishing marker"));
  ("b.inflation",            (16, SevHigh,  "whitespace inflation (scanner-truncation trick)"));
  ("b.hidden_text",          (10, SevMed,   "hidden bait text in html"));
  ("b.tracking_pixel",       (3,  SevLow,   "tracking pixel"));
  ("u.brand_token",          (14, SevHigh,  "brand token outside its real domain"));
  ("u.typosquat",            (16, SevHigh,  "domain close to a brand domain"));
  ("u.credential_path",      (8,  SevMed,   "credential-shaped url path"));
  ("u.shortener",            (5,  SevLow,   "url shortener"));
  ("u.redirector_param",     (9,  SevMed,   "open-redirect style parameter"));
  ("u.punycode",             (9,  SevMed,   "punycode host"));
  ("u.non_ascii_host",       (9,  SevMed,   "non-ascii characters in host"));
  ("u.raw_ip",               (6,  SevMed,   "raw ip host"));
  ("u.no_tls",               (3,  SevLow,   "plain http link"));
  ("u.userinfo",             (7,  SevMed,   "userinfo in url (credential mask)"));
  ("u.odd_scheme",           (5,  SevLow,   "unusual url scheme"));
  ("u.data_html",            (12, SevMed,   "embedded data: html document"));
  ("u.tracking_pixel",       (3,  SevLow,   "tracking pixel"));
  ("u.credential_form",      (30, SevCrit,  "credential form inside embedded document"));
  ("u.form_remote_action",   (10, SevMed,   "embedded form posts off-server"));
  ("u.data_script",          (8,  SevMed,   "script inside embedded document"));
  (* attachments *)
  ("a.exec_ext",             (14, SevHigh,  "executable attachment"));
  ("a.double_ext",           (20, SevHigh,  "double extension (exec behind doc ext)"));
  ("a.masquerade_doc",       (22, SevCrit,  "exec disguised as a document"));
  ("a.rtl_override",         (25, SevCrit,  "bidi override in filename (extension spoof)"));
  ("a.disk_image",           (12, SevMed,   "disk image attachment (mount-and-run)"));
  ("a.macro_office",         (18, SevHigh,  "office macros (vba project)"));
  ("a.legacy_office",        (5,  SevLow,   "legacy office format"));
  ("a.archive",              (3,  SevLow,   "archive attachment"));
  ("a.archive_exec",         (12, SevMed,   "executable inside archive"));
  ("a.pyc_payload",          (16, SevHigh,  "precompiled python bytecode inside archive"));
  ("a.nested_archive",       (6,  SevMed,   "archive inside archive"));
  ("a.pdf_launch",           (18, SevHigh,  "pdf /Launch action"));
  ("a.pdf_openaction",       (8,  SevMed,   "pdf /OpenAction"));
  ("a.pdf_javascript",       (10, SevMed,   "pdf /JavaScript"));
  ("a.pdf_embedded",         (10, SevMed,   "pdf embedded file"));
  ("a.pdf_richmedia",        (8,  SevMed,   "pdf rich media"));
  ("a.pdf_uri",              (3,  SevLow,   "pdf /URI"));
  ("a.pdf_aa",               (6,  SevMed,   "pdf /AA additional actions"));
  ("a.rtf_objdata",          (8,  SevMed,   "rtf embedded object"));
  ("a.html_attachment",      (5,  SevLow,   "html attachment"));
  ("a.att_credential_form",  (28, SevCrit,  "credential form in attached html"));
  ("a.att_data_html",        (12, SevMed,   "embedded data: html in attachment"));
  ("a.att_script",           (8,  SevMed,   "script in attached html"));
  ("a.meta_refresh",         (6,  SevMed,   "meta refresh redirect in attachment"));
  ("a.eicar_test",           (2,  SevInfo,  "eicar test marker (deliberate)"));
  (* template *)
  ("t.ai_template",          (12, SevMed,   "AI-assisted template fingerprints"));
]

let weight_of id = try let (w, _, _) = List.assoc id catalog in w with Not_found -> 0
let sev_of id = try let (_, s, _) = List.assoc id catalog in s with Not_found -> SevInfo
let title_of id = try let (_, _, t) = List.assoc id catalog in t with Not_found -> id

(* force-hostile singletons *)
let force_hostile = [
  "a.rtl_override";
  "u.credential_form";
  "a.att_credential_form";
  "a.masquerade_doc";
  "b.unicode_smuggle"  (* invisible text deliberately hidden from the user *)
]

(* combo force: macros + brand impersonation anywhere;
   scanner-evasion padding + agent-directed instructions *)
let combo_force findings =
  let ids = List.map (fun f -> f.f_id) findings in
  let has id = List.mem id ids in
  (has "a.macro_office" && (has "u.brand_token" || has "h.display_spoof"))
  || (has "b.inflation" && has "b.ctx_manipulation")

type verdict = VClean | VWatch | VSuspicious | VHostile

let verdict_name = function
  | VClean -> "clean" | VWatch -> "watch" | VSuspicious -> "suspicious" | VHostile -> "hostile"

let verdict_of_score score forced =
  if forced then VHostile
  else if score < 10 then VClean
  else if score < 25 then VWatch
  else if score < 60 then VSuspicious
  else VHostile

let exit_of_verdict = function
  | VClean -> 0 | VWatch -> 1 | VSuspicious -> 3 | VHostile -> 10

(* assemble findings from signals *)
let assemble signals =
  let findings = List.filter_map (fun (id, evidence) ->
    if List.mem_assoc id catalog then
      Some { f_id = id; f_sev = sev_of id; f_title = title_of id;
             f_evidence = evidence; f_weight = weight_of id }
    else None) signals in
  (* ai template: single aggregated finding from markers *)
  findings

let verdict_of_findings findings =
  let score = List.fold_left (fun acc f -> acc + f.f_weight) 0 findings in
  let ids = List.map (fun f -> f.f_id) findings in
  let forced =
    List.exists (fun id -> List.mem id force_hostile) ids
    || combo_force findings in
  (verdict_of_score score forced, score, forced)

let max_sev findings =
  List.fold_left (fun acc f ->
    if sev_rank f.f_sev > sev_rank acc then f.f_sev else acc) SevInfo findings
