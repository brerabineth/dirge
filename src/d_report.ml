(* d_report - terminal cards, canonical JSON, markdown *)

let band_color v =
  match v with
  | D_rules.VClean -> D_util.grn
  | D_rules.VWatch -> D_util.yel
  | D_rules.VSuspicious -> (fun s -> D_util.mag s)
  | D_rules.VHostile -> D_util.red

let pad_right n s =
  let l = D_util.cp_count s in
  if l >= n then s else s ^ String.make (n - l) ' '

let pad_left n s =
  let l = D_util.cp_count s in
  if l >= n then s else String.make (n - l) ' ' ^ s

(* ---------- terminal ---------- *)

let card (r : D_scan.scan_result) =
  let buf = Buffer.create 4096 in
  let b = Format.formatter_of_buffer buf in
  let p f = Format.fprintf b f in
  let vc = band_color r.D_scan.sr_verdict in
  p "%s@." D_util.sep;
  p "%s  %s  score %s%s@."
    (vc (String.uppercase_ascii (D_rules.verdict_name r.D_scan.sr_verdict)))
    (D_util.dim (r.D_scan.sr_path))
    (if r.D_scan.sr_forced then D_util.bold (string_of_int r.D_scan.sr_score) else string_of_int r.D_scan.sr_score)
    (if r.D_scan.sr_forced then D_util.bold " (forced)" else "");
  (try
     let get k = try List.assoc k r.D_scan.sr_summary with Not_found -> "" in
     p "  from    %s@." (get "from");
     p "  subject %s@." (get "subject");
     p "  date    %s@." (get "date");
     p "  auth    %s   received: %s@." (get "auth") (get "received")
   with _ -> ());
  p "%s@." D_util.sep;
  (* findings grouped by severity desc *)
  let findings = List.sort (fun a b ->
    compare (D_rules.sev_rank b.D_rules.f_sev) (D_rules.sev_rank a.D_rules.f_sev)) r.D_scan.sr_findings in
  if findings = [] then p "  %s@." (D_util.grn "no findings")
  else
    List.iter (fun f ->
      let sev_c = match f.D_rules.f_sev with
        | D_rules.SevCrit -> D_util.red
        | D_rules.SevHigh -> D_util.red
        | D_rules.SevMed -> D_util.yel
        | D_rules.SevLow -> D_util.cya
        | D_rules.SevInfo -> D_util.dim in
      p "  [%s] %s@." (sev_c (D_rules.sev_name f.D_rules.f_sev)) f.D_rules.f_title;
      List.iter (fun e ->
        p "        %s@." (D_util.dim (D_util.mask_secrets e))) f.D_rules.f_evidence) findings;
  (* attachments *)
  if r.D_scan.sr_atts <> [] then begin
    p "  attachments:@.";
    List.iter (fun a ->
      p "    %s  %s %s@."
        (pad_right 36 (D_util.clip 36 a.D_attach.at_name))
        (D_util.dim (Printf.sprintf "%d B" a.D_attach.at_size))
        (D_util.dim (String.concat "," a.D_attach.at_flags))) r.D_scan.sr_atts
  end;
  (* urls *)
  let flagged = List.filter (fun u -> u.D_url.u_flags <> []) r.D_scan.sr_urls in
  if flagged <> [] then begin
    p "  flagged urls:@.";
    List.iter (fun u ->
      p "    %s  %s@."
        (D_util.defang (D_util.clip 52 u.D_url.u_raw))
        (D_util.dim (String.concat "," u.D_url.u_flags))) (let rec take n l = if n = 0 then [] else match l with x :: r -> x :: take (n - 1) r | [] -> [] in take 8 flagged)
  end;
  (* ai template *)
  if r.D_scan.sr_ai <> "none" then
    p "  ai-template: %s %s@." (D_util.mag r.D_scan.sr_ai)
      (D_util.dim (Printf.sprintf "(%d fingerprints)" (List.length r.D_scan.sr_ai_markers)));
  (* warnings *)
  List.iter (fun w -> p "  warning: %s@." (D_util.dim w)) r.D_scan.sr_warnings;
  Format.pp_print_flush b ();
  Buffer.contents buf

let terminal results =
  let buf = Buffer.create 8192 in
  Buffer.add_string buf D_util.banner;
  Buffer.add_string buf "\n\n";
  (* summary table *)
  Buffer.add_string buf "  case                              verdict     score\n";
  Buffer.add_string buf D_util.sep;
  Buffer.add_char buf '\n';
  List.iter (fun r ->
    let vname = String.uppercase_ascii (D_rules.verdict_name r.D_scan.sr_verdict) in
    let name = D_util.clip 32 (Filename.basename r.D_scan.sr_path) in
    Buffer.add_string buf
      (Printf.sprintf "  %-32s  %s   %s%s\n"
         (pad_right 32 name)
         (pad_right 10 ((band_color r.D_scan.sr_verdict) vname))
         (if r.D_scan.sr_score >= 100 then "" else " ")
         (let sc = string_of_int r.D_scan.sr_score in
          (band_color r.D_scan.sr_verdict) sc))) results;
  Buffer.add_string buf "\n";
  List.iter (fun r -> Buffer.add_string buf (card r); Buffer.add_char buf '\n') results;
  Buffer.contents buf

(* ---------- json (canonical: sorted keys, single line) ---------- *)

let json_escape s =
  let buf = Buffer.create (String.length s + 8) in
  String.iter (fun c ->
    match c with
    | '"' -> Buffer.add_string buf "\\\""
    | '\\' -> Buffer.add_string buf "\\\\"
    | '\n' -> Buffer.add_string buf "\\n"
    | '\r' -> Buffer.add_string buf "\\r"
    | '\t' -> Buffer.add_string buf "\\t"
    | c when Char.code c < 0x20 -> Buffer.add_string buf (Printf.sprintf "\\u%04x" (Char.code c))
    | c -> Buffer.add_char buf c) s;
  Buffer.contents buf

let jstr s = "\"" ^ json_escape s ^ "\""

(* canonical json array from string list *)
let jarr xs = "[" ^ String.concat "," (List.map jstr xs) ^ "]"

let sort_pairs (a, b) = compare a b

(* generic sorted-key object builder *)
let jobj (pairs : (string * string) list) =
  let pairs = List.sort (fun (a, _) (b, _) -> compare a b) pairs in
  "{" ^ String.concat "," (List.map (fun (k, v) -> jstr k ^ ":" ^ v) pairs) ^ "}"

let finding_json f =
  jobj [
    "evidence", jarr (List.map D_util.mask_secrets f.D_rules.f_evidence);
    "id", jstr f.D_rules.f_id;
    "severity", jstr (D_rules.sev_name f.D_rules.f_sev);
    "title", jstr f.D_rules.f_title;
    "weight", string_of_int f.D_rules.f_weight;
  ]

let att_json a =
  jobj [
    "flags", jarr a.D_attach.at_flags;
    "name", jstr a.D_attach.at_name;
    "size", string_of_int a.D_attach.at_size;
    "type", jstr a.D_attach.at_type;
  ]

let url_json u =
  let payload_flag = if u.D_url.u_payload <> "" then "with_payload" else "empty" in
  jobj [
    "flags", jarr u.D_url.u_flags;
    "host", jstr u.D_url.u_host;
    "kind", jstr u.D_url.u_kind;
    "payload", jstr payload_flag;
    "raw", jstr (D_util.defang u.D_url.u_raw);
  ]

let result_json r =
  jobj [
    "ai_template", jstr r.D_scan.sr_ai;
    "attachments", "[" ^ String.concat "," (List.map att_json r.D_scan.sr_atts) ^ "]";
    "findings", "[" ^ String.concat "," (List.map finding_json
      (List.sort (fun a b -> compare a.D_rules.f_id b.D_rules.f_id) r.D_scan.sr_findings)) ^ "]";
    "forced", (if r.D_scan.sr_forced then "true" else "false");
    "path", jstr r.D_scan.sr_path;
    "score", string_of_int r.D_scan.sr_score;
    "summary", jobj (List.map (fun (k, v) -> (k, jstr v)) r.D_scan.sr_summary);
    "urls", "[" ^ String.concat "," (List.map url_json r.D_scan.sr_urls) ^ "]";
    "verdict", jstr (D_rules.verdict_name r.D_scan.sr_verdict);
    "warnings", jarr r.D_scan.sr_warnings;
  ]

let json results =
  let counts = List.map (fun r -> D_rules.verdict_name r.D_scan.sr_verdict) results in
  let count k = List.length (List.filter (fun v -> v = k) counts) in
  jobj [
    "results", "[" ^ String.concat "," (List.map result_json results) ^ "]";
    "summary", jobj [
      "clean", string_of_int (count "clean");
      "hostile", string_of_int (count "hostile");
      "suspicious", string_of_int (count "suspicious");
      "total", string_of_int (List.length results);
      "watch", string_of_int (count "watch");
    ];
    "tool", jstr "dirge";
    "version", jstr D_util.version;
  ]

(* ---------- markdown ---------- *)

let md results =
  let buf = Buffer.create 4096 in
  Buffer.add_string buf "# dirge triage report\n\n";
  Buffer.add_string buf "| case | verdict | score | findings |\n|---|---|---|---|\n";
  List.iter (fun r ->
    let tops = List.sort (fun a b ->
      compare (D_rules.sev_rank b.D_rules.f_sev) (D_rules.sev_rank a.D_rules.f_sev)) r.D_scan.sr_findings in
    let top_ids = List.map (fun f -> "`" ^ f.D_rules.f_id ^ "`")
      (let rec take n l = if n = 0 then [] else match l with x :: r -> x :: take (n - 1) r | [] -> [] in take 5 tops) in
    Buffer.add_string buf
      (Printf.sprintf "| %s | %s | %d | %s |\n"
         (Filename.basename r.D_scan.sr_path)
         (D_rules.verdict_name r.D_scan.sr_verdict)
         r.D_scan.sr_score
         (String.concat " " top_ids))) results;
  Buffer.add_string buf "\n## iocs\n\n";
  let all_urls = List.concat_map (fun r -> r.D_scan.sr_urls) results in
  let flagged = List.filter (fun u -> u.D_url.u_flags <> []) all_urls in
  if flagged = [] then Buffer.add_string buf "none\n"
  else begin
    Buffer.add_string buf "```\n";
    List.iter (fun u ->
      Buffer.add_string buf (D_util.defang (D_util.clip 90 u.D_url.u_raw));
      Buffer.add_char buf '\n') flagged;
    Buffer.add_string buf "```\n"
  end;
  Buffer.add_string buf "\n## attachments\n\n";
  let all_atts = List.concat_map (fun r -> r.D_scan.sr_atts) results in
  if all_atts = [] then Buffer.add_string buf "none\n"
  else
    List.iter (fun a ->
      Buffer.add_string buf
        (Printf.sprintf "- %s (%d B) %s\n" a.D_attach.at_name a.D_attach.at_size
           (String.concat "," a.D_attach.at_flags))) all_atts;
  Buffer.contents buf
