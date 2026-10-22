(* d_headers - From/Reply-To/Return-Path/Authentication-Results/Received forensics *)

type addr = { a_name : string; a_email : string }

let parse_addrs value =
  let decoded = D_rfc2047.decode value in
  (* split on commas outside quotes and angle brackets *)
  let n = String.length decoded in
  let items = ref [] and item = Buffer.create 64 in
  let inq = ref false and ang = ref 0 in
  for i = 0 to n - 1 do
    let c = decoded.[i] in
    if c = '"' && (i = 0 || decoded.[i - 1] <> '\\') then (inq := not !inq; Buffer.add_char item c)
    else if c = '<' then (incr ang; Buffer.add_char item c)
    else if c = '>' then (if !ang > 0 then decr ang; Buffer.add_char item c)
    else if c = ',' && not !inq && !ang = 0 then (items := Buffer.contents item :: !items; Buffer.clear item)
    else Buffer.add_char item c
  done;
  items := Buffer.contents item :: !items;
  List.filter_map (fun it ->
    let it = D_util.trim it in
    if it = "" then None
    else match String.index_opt it '<' with
      | Some lt when D_util.ends_with it ">" ->
        let name0 = D_util.trim (String.sub it 0 lt) in
        let name =
          if String.length name0 >= 2 && name0.[0] = '"' && name0.[String.length name0 - 1] = '"' then
            String.sub name0 1 (String.length name0 - 2)
          else name0 in
        let email = String.sub it (lt + 1) (String.length it - lt - 2) in
        Some { a_name = D_util.trim name; a_email = String.lowercase_ascii (D_util.trim email) }
      | _ ->
        (* bare email or quoted name without <> *)
        let toks = String.split_on_char ' ' it |> List.filter (fun x -> x <> "") in
        (match List.filter (fun t -> D_util.contains_ci t "@") toks with
         | [e] -> Some { a_name = D_util.trim (String.concat " " (List.filter (fun t -> not (D_util.contains_ci t "@")) toks)); a_email = String.lowercase_ascii (D_util.trim e) }
         | _ -> Some { a_name = it; a_email = "" })
  ) (List.rev !items)

let domain_of email =
  match String.rindex_opt email '@' with
  | Some at -> String.lowercase_ascii (String.sub email (at + 1) (String.length email - at - 1))
  | None -> ""

(* RFC5322 date subset -> epoch seconds *)
let month_of m =
  match String.lowercase_ascii m with
  | "jan" -> 1 | "feb" -> 2 | "mar" -> 3 | "apr" -> 4 | "may" -> 5 | "jun" -> 6
  | "jul" -> 7 | "aug" -> 8 | "sep" -> 9 | "oct" -> 10 | "nov" -> 11 | "dec" -> 12
  | _ -> 0

let days_from_civil y m d =
  (* Howard Hinnant's algorithm *)
  let y = if m <= 2 then y - 1 else y in
  let era = (if y >= 0 then y else y - 399) / 400 in
  let yoe = y - era * 400 in
  let mp = (m + 9) mod 12 in
  let doy = (153 * mp + 2) / 5 + d - 1 in
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy in
  era * 146097 + doe - 719468

let zone_offset z =
  let z = String.uppercase_ascii (D_util.trim z) in
  match z with
  | "UT" | "GMT" | "UTC" | "Z" -> 0
  | "EST" -> -5 * 3600 | "EDT" -> -4 * 3600
  | "CST" -> -6 * 3600 | "CDT" -> -5 * 3600
  | "MST" -> -7 * 3600 | "MDT" -> -6 * 3600
  | "PST" -> -8 * 3600 | "PDT" -> -7 * 3600
  | _ ->
    if String.length z >= 5 && (z.[0] = '+' || z.[0] = '-') then begin
      let ok =
        (fun s -> String.for_all (fun c -> c >= '0' && c <= '9') s)
          (String.sub z 1 4) in
      if ok then begin
        let h = int_of_string (String.sub z 1 2) in
        let m = int_of_string (String.sub z 3 2) in
        let sign = if z.[0] = '-' then -1 else 1 in
        sign * (h * 3600 + m * 60)
      end else 0
    end else 0

let parse_date value =
  let toks = String.split_on_char ' ' value |> List.map D_util.trim |> List.filter (fun x -> x <> "") in
  let toks = List.filter (fun t ->
    let l = String.length t in
    l = 0 || t.[l - 1] <> ',') toks in
  (* find day (1-2 digits), month alpha, year (4 or 2 digits), time hh:mm[:ss], zone *)
  let day = ref None and mon = ref 0 and year = ref 0 and hh = ref 0 and mm = ref 0 and ss = ref 0 and zone = ref 0 in
  List.iteri (fun i t ->
    if String.length t >= 1 && String.for_all (fun c -> c >= '0' && c <= '9') t && String.length t <= 2 && !day = None then
      day := Some (int_of_string t)
    else if String.length t = 3 && !mon = 0 && month_of t > 0 then mon := month_of t
    else if String.length t >= 2 && String.for_all (fun c -> c >= '0' && c <= '9') t && i > 0 && !year = 0 && String.length t <= 4 && (String.length t = 4 || String.length t = 2) && !day <> None then
      year := (if String.length t = 2 then (if int_of_string t < 50 then 2000 + int_of_string t else 1900 + int_of_string t) else int_of_string t)
    else if String.contains t ':' && !mm = 0 && !hh = 0 then begin
      let parts = String.split_on_char ':' t in
      (match parts with
       | h :: m :: rest ->
         (try hh := int_of_string h; mm := int_of_string m;
              (match rest with s :: _ -> ss := int_of_string s | [] -> ())
          with _ -> ())
       | _ -> ())
    end else if (String.length t = 5 && (t.[0] = '+' || t.[0] = '-')) || String.length t = 2 || String.length t = 3 then begin
      if t.[0] = '+' || t.[0] = '-' || month_of t = 0 then
        if String.length t >= 2 && (t.[0] = '+' || t.[0] = '-') then zone := zone_offset t
        else if String.length t <= 3 && !zone = 0 && month_of t = 0 then zone := zone_offset t
    end) toks;
  match !day with
  | Some d when !mon > 0 && !year > 0 ->
    Some (days_from_civil !year !mon d * 86400 + !hh * 3600 + !mm * 60 + !ss - !zone)
  | _ -> None

(* extract ipv4-ish tokens from a received from-clause *)
let ips_in s =
  let n = String.length s in
  let acc = ref [] in
  let i = ref 0 in
  while !i < n do
    let is_dig c = c >= '0' && c <= '9' in
    if is_dig s.[!i] then begin
      let j = ref !i in
      while !j < n && (is_dig s.[!j] || s.[!j] = '.') do incr j done;
      let tok = String.sub s !i (!j - !i) in
      let parts = String.split_on_char '.' tok in
      if List.length parts = 4 && List.for_all (fun p -> p <> "" && String.length p <= 3 && String.for_all (fun c -> c >= '0' && c <= '9') p) parts then
        acc := tok :: !acc;
      i := !j
    end else incr i
  done;
  List.rev !acc

type auth = { spf : string; dkim : string; dmarc : string; present : bool }

let parse_auth values =
  (* first Authentication-Results header with any verdict wins *)
  let parse_one v =
    let get key =
      match D_util.find_ci v (key ^ "=") with
      | Some i ->
        let rest = String.sub v (i + String.length key + 1) (String.length v - i - String.length key - 1) in
        let stops = [D_util.find_ci rest ";"; D_util.find_ci rest " "] in
        let len = List.fold_left (fun acc o ->
          match o with
          | Some p when acc < 0 || p < acc -> p
          | _ -> acc) (-1) stops in
        let len = if len < 0 then String.length rest else len in
        String.lowercase_ascii (D_util.trim (String.sub rest 0 len))
      | None -> ""
    in
    let spf = get "spf" and dkim = get "dkim" and dmarc = get "dmarc" in
    { spf; dkim; dmarc; present = spf <> "" || dkim <> "" || dmarc <> "" }
  in
  let rec pick = function
    | [] -> { spf = ""; dkim = ""; dmarc = ""; present = false }
    | v :: rest -> let a = parse_one v in if a.present then a else pick rest
  in
  pick values

type header_ctx = {
  h_from : addr option;
  h_reply_to : addr list;
  h_return_path : string;
  h_msgid : string;
  h_subject : string;
  h_date : string;
  h_date_epoch : int option;
  h_received : string list;
  h_auth : auth;
  h_has_dkim_sig : bool;
  h_is_list : bool;
  h_ar_count : int;
}

let ctx_of root =
  let hdrs = root.D_mime.p_headers in
  let from =
    match D_mime.hdr hdrs "from" with
    | Some v -> (match parse_addrs v with a :: _ -> Some a | [] -> None)
    | None -> None
  in
  let reply_to =
    match D_mime.hdr hdrs "reply-to" with
    | Some v -> parse_addrs v
    | None -> []
  in
  let return_path = match D_mime.hdr hdrs "return-path" with Some v -> v | None -> "" in
  let msgid = match D_mime.hdr hdrs "message-id" with Some v -> v | None -> "" in
  let subject = match D_mime.hdr hdrs "subject" with Some v -> D_rfc2047.decode v | None -> "" in
  let date = match D_mime.hdr hdrs "date" with Some v -> v | None -> "" in
  let received = D_mime.hdr_all hdrs "received" in
  let ars = D_mime.hdr_all hdrs "authentication-results" in
  {
    h_from = from;
    h_reply_to = reply_to;
    h_return_path = return_path;
    h_msgid = msgid;
    h_subject = subject;
    h_date = date;
    h_date_epoch = (if date = "" then None else parse_date date);
    h_received = received;
    h_auth = parse_auth ars;
    h_has_dkim_sig = List.exists (fun (k, _) -> k = "dkim-signature") hdrs;
    h_is_list =
      List.exists (fun (k, _) -> k = "list-id" || k = "list-unsubscribe") hdrs;
    h_ar_count = List.length ars;
  }

(* signal id + evidence lines *)
type signal = string * string list

let ev_line s = D_util.clip 96 (D_util.strip_invisible (D_util.mask_secrets s))

let ctx_signals ctx : signal list =
  let out = ref [] in
  let add id ev = out := (id, List.map ev_line ev) :: !out in
  let from_dom = match ctx.h_from with Some a -> domain_of a.a_email | None -> "" in
  (* from *)
  (match ctx.h_from with
   | None -> add "h.no_from" ["no parsable From header"]
   | Some a ->
     if a.a_email = "" then add "h.no_from" ["From has no addr-spec: " ^ a.a_name]);
  (* auth *)
  let a = ctx.h_auth in
  if not a.present && not ctx.h_has_dkim_sig then
    add "h.auth_missing" ["no Authentication-Results, no DKIM-Signature"]
  else begin
    if a.present then begin
      if D_util.starts_with a.spf "fail" then add "h.spf_fail" ["spf=" ^ a.spf]
      else if D_util.starts_with a.spf "softfail" then add "h.spf_softfail" ["spf=" ^ a.spf]
      else if D_util.starts_with a.spf "neutral" then add "h.spf_neutral" ["spf=" ^ a.spf]
      else if D_util.starts_with a.spf "none" && from_dom <> "" then add "h.spf_none" ["spf=" ^ a.spf];
      if D_util.starts_with a.dkim "fail" then add "h.dkim_fail" ["dkim=" ^ a.dkim]
      else if a.dkim = "none" && not ctx.h_has_dkim_sig then add "h.dkim_none" ["dkim=none, no signature"];
      if D_util.starts_with a.dmarc "fail" then add "h.dmarc_fail" ["dmarc=" ^ a.dmarc]
    end
  end;
  (* domain mismatches, suppressed on mailing-list traffic *)
  if not ctx.h_is_list then begin
    (match ctx.h_reply_to with
     | r :: _ when r.a_email <> "" && from_dom <> "" ->
       let rd = domain_of r.a_email in
       if rd <> "" && rd <> from_dom && not (D_util.ends_with from_dom ("." ^ rd)) then
         add "h.replyto_mismatch"
           ["reply-to " ^ D_util.defang (r.a_email) ^ " vs from " ^ D_util.defang (from_dom)]
     | _ -> ());
    if ctx.h_return_path <> "" && from_dom <> "" then begin
      let rp = ctx.h_return_path in
      let rp_email =
        match String.index_opt rp '<' with
        | Some lt when D_util.ends_with rp ">" -> String.sub rp (lt + 1) (String.length rp - lt - 2)
        | _ -> rp
      in
      let rpd = domain_of (String.lowercase_ascii rp_email) in
      if rpd <> "" && rpd <> from_dom && not (D_util.ends_with from_dom ("." ^ rpd)) then
        add "h.returnpath_mismatch" ["return-path " ^ D_util.defang rp_email ^ " vs from " ^ D_util.defang from_dom]
    end;
    if ctx.h_msgid <> "" && from_dom <> "" then begin
      let mid = String.lowercase_ascii ctx.h_msgid in
      match String.index_opt mid '@' with
      | Some at when D_util.ends_with mid ">" ->
        let md = String.sub mid (at + 1) (String.length mid - at - 2) in
        if md <> "" && md <> from_dom && not (D_util.ends_with from_dom ("." ^ md)) && not (D_util.contains_ci md "local") then
          add "h.msgid_mismatch" ["message-id domain " ^ D_util.defang md ^ " vs from " ^ D_util.defang from_dom]
      | _ -> ()
    end
  end;
  (* structural *)
  if ctx.h_msgid = "" then add "h.msgid_missing" ["no Message-ID"];
  if ctx.h_date = "" then add "h.date_missing" ["no Date header"];
  if ctx.h_received = [] then add "h.no_received" ["no Received chain (direct injection or hand-crafted)"];
  (* date vs first received *)
  (match ctx.h_date_epoch, ctx.h_received with
   | Some d, r0 :: _ ->
     (* received line: ...; date *)
     (match String.rindex_opt r0 ';' with
      | Some semi ->
        let rd = String.sub r0 (semi + 1) (String.length r0 - semi - 1) in
        (match parse_date rd with
         | Some rd_epoch ->
           let skew = abs (d - rd_epoch) in
           if skew > 48 * 3600 then
             add "h.date_skew"
               [Printf.sprintf "Date vs first Received skew %d h" (skew / 3600);
                "date: " ^ D_util.clip 40 ctx.h_date;
                "recv: " ^ D_util.clip 40 (D_util.trim rd)]
         | None -> ())
      | None -> ())
   | _ -> ());
  (* display-name brand spoof *)
  (match ctx.h_from with
   | Some a when a.a_name <> "" && from_dom <> "" ->
     let nm = String.lowercase_ascii a.a_name in
     List.iter (fun (token, legit) ->
       if D_util.contains_ci nm token then begin
         let reg = D_util.registrable from_dom in
         let ok = List.exists (fun ld -> reg = D_util.registrable ld || D_util.ends_with reg ("." ^ D_util.registrable ld)) legit in
         if not ok then
           add "h.display_spoof"
             [Printf.sprintf "display name claims %s, from %s" token (D_util.defang from_dom)]
       end) D_util.brands
   | _ -> ());
  (* subject unicode smuggling *)
  (match D_util.suspicious_unicode ctx.h_subject with
   | [] -> ()
   | classes ->
     add "h.subj_unicode"
       (List.map (fun (c, n) -> Printf.sprintf "subject: %s x%d" c n) classes));
  (* unknown charsets *)
  (match !D_rfc2047.unknown_charsets with
   | [] -> ()
   | css -> add "h.unknown_charset" ["exotic charset(s): " ^ String.concat ", " css]);
  List.rev !out

(* display fields for report *)
let ctx_summary ctx =
  let from = match ctx.h_from with
    | Some a ->
      if a.a_name <> "" then a.a_name ^ " <" ^ a.a_email ^ ">"
      else a.a_email
    | None -> "?" in
  let a = ctx.h_auth in
  let auth =
    if not a.present && not ctx.h_has_dkim_sig then "none"
    else Printf.sprintf "spf=%s dkim=%s dmarc=%s"
      (if a.spf = "" then "-" else a.spf)
      (if a.dkim = "" then (if ctx.h_has_dkim_sig then "signed" else "-") else a.dkim)
      (if a.dmarc = "" then "-" else a.dmarc)
  in
  [ "from", D_util.strip_invisible from;
    "subject", D_util.strip_invisible ctx.h_subject;
    "date", D_util.trim ctx.h_date;
    "auth", auth;
    "received", string_of_int (List.length ctx.h_received) ]
