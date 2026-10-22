(* d_scan - body heuristics + orchestration into a scan result *)

type scan_result = {
  sr_path : string;
  sr_summary : (string * string) list;
  sr_findings : D_rules.finding list;
  sr_verdict : D_rules.verdict;
  sr_score : int;
  sr_forced : bool;
  sr_urls : D_url.url_info list;
  sr_atts : D_attach.att_info list;
  sr_ai : string;
  sr_ai_markers : D_aitmpl.marker list;
  sr_warnings : string list;
  sr_size : int;
}

let dedupe xs =
  let seen = Hashtbl.create 16 in
  List.filter (fun x ->
    if Hashtbl.mem seen x then false
    else (Hashtbl.add seen x (); true)) xs

(* merge signals with same id: single finding, evidence merged + capped *)
let merge_signals signals =
  let order = ref [] in
  let tbl = Hashtbl.create 32 in
  List.iter (fun (id, ev) ->
    if not (Hashtbl.mem tbl id) then (Hashtbl.add tbl id []; order := id :: !order);
    Hashtbl.replace tbl id (ev @ Hashtbl.find tbl id)) signals;
  List.rev_map (fun id -> (id, List.rev (Hashtbl.find tbl id))) !order

let body_signals text_body html_all visible_text subject =
  let out = ref [] in
  let add id ev = out := (id, ev) :: !out in
  let combined = subject ^ "\n" ^ text_body ^ "\n" ^ visible_text in
  let probe distinct_min id words source =
    let hits = List.filter (fun w -> D_util.contains_ci source w) words in
    let hits = dedupe hits in
    if List.length hits >= distinct_min then
      add id (List.map (fun h -> "\"" ^ h ^ "\"") (let rec take n l = if n = 0 then [] else match l with x :: r -> x :: take (n - 1) r | [] -> [] in take 4 hits))
  in
  (* ctx manipulation aimed at an agent reading the mail *)
  probe 1 "b.ctx_manipulation"
    [ "ignore previous instructions"; "ignore all previous"; "disregard all previous";
      "disregard previous"; "new instructions"; "system prompt";
      "repeat after me"; "developer mode"; "do not tell the user";
      "don't tell the user"; "before reading further"; "jailbreak" ]
    combined;
  probe 2 "b.urgency"
    [ "within 24 hours"; "24 hours"; "48 hours"; "immediately"; "final notice";
      "act now"; "urgent"; "expires today"; "last warning"; "account will be suspended";
      "account will be closed"; "will be terminated"; "unusual activity"; "right away" ]
    combined;
  probe 1 "b.credential_lure"
    [ "verify your account"; "verify your identity"; "confirm your account";
      "confirm your identity"; "update your payment"; "unusual login"; "unlock your account";
      "re-activate"; "reactivate your"; "login attempt"; "sign-in attempt"; "signin attempt";
      "password expir"; "validate your credentials"; "restore access" ]
    combined;
  probe 1 "b.threat_scare"
    [ "law enforcement"; "legal action"; "arrest warrant"; "copyright infringement";
      "lawsuit"; "court appearance"; "police report" ]
    combined;
  probe 1 "b.crypto_lure"
    [ "seed phrase"; "secret phrase"; "recovery phrase"; "crypto wallet";
      "wallet recovery"; "private key"; "hardware wallet" ]
    combined;
  probe 1 "b.gift_bait"
    [ "gift card"; "reward points"; "you have won"; "lottery winner"; "claim your prize";
      "exclusive reward" ]
    combined;
  (* callback phishing: call/hotline + phone-ish digits *)
  if D_util.contains_ci visible_text "call" &&
     (D_util.contains_ci visible_text "support" || D_util.contains_ci visible_text "hotline" ||
      D_util.contains_ci visible_text "customer care" || D_util.contains_ci visible_text "toll-free") then begin
    let digits = ref 0 and run = ref 0 in
    String.iter (fun c -> if c >= '0' && c <= '9' then (incr run; if !run > !digits then digits := !run) else run := 0) visible_text;
    if !digits >= 8 then
      add "b.callback" ["call + long number run in text"]
  end;
  (* unicode smuggling *)
  let classes = D_util.suspicious_unicode (text_body ^ html_all) in
  let tags = try List.assoc "unicode_tags" classes with Not_found -> 0 in
  let bidi = try List.assoc "bidi_control" classes with Not_found -> 0 in
  let zero = try List.assoc "zero_width" classes with Not_found -> 0 in
  if tags >= 1 || bidi >= 1 || zero >= 5 then
    add "b.unicode_smuggle"
      (List.map (fun (c, n) -> Printf.sprintf "%s x%d" c n) classes);
  (* whitespace inflation (trail of bits truncation trick) *)
  let max_nl_run s =
    let run = ref 0 and best = ref 0 in
    String.iter (fun c -> if c = '\n' then (incr run; if !run > !best then best := !run) else run := 0) s;
    !best
  in
  let infl = max (max_nl_run text_body) (max_nl_run html_all) in
  if infl >= 5000 then
    add "b.inflation" [Printf.sprintf "%d consecutive newlines (oversize padding)" infl];
  (* hidden bait text *)
  (match D_url.hidden_text_hits html_all with
   | [] -> ()
   | probes -> add "b.hidden_text" probes);
  !out

let url_signals urls =
  let out = ref [] in
  (* aggregate by flag: one signal per flag, evidence up to 3 urls *)
  let all_flags =
    List.concat_map (fun u -> List.map (fun f -> (f, u)) u.D_url.u_flags) urls
    |> List.sort_uniq (fun (a, _) (b, _) -> compare a b) in
  List.iter (fun (flag, _) ->
    let evid =
      urls
      |> List.filter (fun u -> List.mem flag u.D_url.u_flags)
      |> (fun l -> let rec take n l = if n = 0 then [] else match l with x :: r -> x :: take (n - 1) r | [] -> [] in take 3 l)
      |> List.map (fun u ->
        match u.D_url.u_kind with
        | "data" -> "data:" ^ String.concat "," u.D_url.u_flags
        | _ -> D_util.defang (D_util.clip 64 u.D_url.u_raw))
    in
    out := ("u." ^ flag, evid) :: !out) all_flags;
  !out

let att_signals atts =
  let out = ref [] in
  List.iter (fun a ->
    List.iter (fun f ->
      out := ("a." ^ f, [Printf.sprintf "%s (%d bytes)" (D_util.clip 40 a.D_attach.at_name) a.D_attach.at_size]) :: !out) a.D_attach.at_flags) atts;
  !out

let scan_raw path raw =
  D_mime.reset_warn ();
  D_rfc2047.reset_unknown ();
  let root = D_mime.parse raw in
  let ctx = D_headers.ctx_of root in
  let hsignals = D_headers.ctx_signals ctx in
  let text_body, _ = D_mime.best_text root in
  let html_parts = D_mime.html_parts root in
  let html_all = String.concat "\n" (List.map (fun p -> p.D_mime.p_body_decoded) html_parts) in
  let visible_text = D_url.html_text html_all in
  let urls =
    let from_html = D_url.analyze_html html_all in
    let from_text = D_url.scan_text text_body "body" in
    let seen = Hashtbl.create 16 in
    List.filter (fun u ->
      if Hashtbl.mem seen u.D_url.u_raw then false
      else (Hashtbl.add seen u.D_url.u_raw (); true)) (from_html @ from_text)
  in
  let atts = D_attach.analyze root in
  let bsignals = body_signals text_body html_all visible_text ctx.D_headers.h_subject in
  let usignals = url_signals urls in
  let asignals = att_signals atts in
  (* ai template assessment only when html present *)
  let ai, markers =
    if html_all = "" then ("none", [])
    else D_aitmpl.assess html_all
  in
  let tsignal =
    if ai = "none" then []
    else [("t.ai_template",
           (Printf.sprintf "AI-template likelihood: %s" ai) ::
           (List.map (fun m -> m.D_aitmpl.m_evidence)
              (let rec take n l = if n = 0 then [] else match l with x :: r -> x :: take (n - 1) r | [] -> [] in take 4 markers)))] in
  let signals = hsignals @ bsignals @ usignals @ asignals @ tsignal in
  let merged = merge_signals signals in
  let findings = D_rules.assemble merged in
  let verdict, score, forced = D_rules.verdict_of_findings findings in
  {
    sr_path = path;
    sr_summary = D_headers.ctx_summary ctx;
    sr_findings = findings;
    sr_verdict = verdict;
    sr_score = score;
    sr_forced = forced;
    sr_urls = urls;
    sr_atts = atts;
    sr_ai = ai;
    sr_ai_markers = markers;
    sr_warnings = List.rev !D_mime.parse_warnings;
    sr_size = String.length raw;
  }
