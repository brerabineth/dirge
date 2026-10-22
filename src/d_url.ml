(* d_url - url extraction (text + html), risk classification, data-uri payload *)

type url_info = {
  u_raw : string;       (* display form (clipped) *)
  u_host : string;
  u_scheme : string;
  u_flags : string list;
  u_kind : string;      (* link | href | src | data | body *)
  u_payload : string;   (* decoded data-uri body, else "" *)
}

let shorteners = [
  "bit.ly"; "tinyurl.com"; "t.co"; "is.gd"; "goo.gl"; "cutt.ly"; "ow.ly";
  "buff.ly"; "rebrand.ly"; "shorturl.at"; "rb.gy"; "t.ly"; "s.id"; "lnkd.in";
  "bit.do"; "clck.ru"; "u.to"; "qr.ae"; "v.gd"
]

let redirect_params = [
  "url="; "u="; "redirect="; "redirect_uri="; "next="; "goto="; "dest=";
  "destination="; "continue="; "return="; "returnurl="; "target="; "link="
]

let cred_words = ["login"; "log-in"; "signin"; "sign-in"; "verify"; "verification";
                  "secure"; "account"; "update"; "confirm"; "password"; "webscr";
                  "wallet"; "seed"; "recovery"; "unlock"; "billing"; "renew"]

let url_flags host path query scheme =
  let flags = ref [] in
  let add f = if not (List.mem f !flags) then flags := f :: !flags in
  (* host checks *)
  if D_util.starts_with host "xn--" || D_util.contains_ci host ".xn--" then add "punycode";
  String.iter (fun c -> if Char.code c >= 128 then add "non_ascii_host") host;
  (* raw ip *)
  let segs = String.split_on_char '.' host in
  if List.length segs = 4 &&
     List.for_all (fun p -> p <> "" && String.length p <= 3 &&
                            String.for_all (fun c -> c >= '0' && c <= '9') p) segs then
    add "raw_ip";
  if List.mem host shorteners then add "shortener";
  (* brand token outside legit domain *)
  let reg = D_util.registrable host in
  List.iter (fun (token, legit) ->
    if D_util.contains_ci host token then begin
      let ok = List.exists (fun ld ->
        let lreg = D_util.registrable ld in
        reg = lreg || D_util.ends_with reg ("." ^ lreg) || D_util.ends_with lreg ("." ^ reg)) legit in
      if not ok then add "brand_token"
    end) D_util.brands;
  (* typosquat distance against brand registrable domains *)
  List.iter (fun (token, legit) ->
    List.iter (fun ld ->
      let lreg = D_util.registrable ld in
      let d = D_util.levenshtein reg lreg in
      if d <= 2 && reg <> lreg && not (D_util.contains_ci reg lreg) &&
         not (D_util.contains_ci lreg reg) && String.length reg >= 5 then add "typosquat")
      legit) D_util.brands;
  (* scheme *)
  if scheme = "http" then add "no_tls";
  if scheme = "ftp" || scheme = "file" then add "odd_scheme";
  (* credential-ish path *)
  if List.exists (fun w -> D_util.contains_ci path w || D_util.contains_ci query w) cred_words then
    add "credential_path";
  (* open redirect param with absolute url value *)
  if List.exists (fun p -> D_util.contains_ci query p) redirect_params &&
     (D_util.contains_ci query "http%3a" || D_util.contains_ci query "http://" ||
      D_util.contains_ci query "https%3a" || D_util.contains_ci query "https://") then
    add "redirector_param";
  !flags

(* html entity decode *)
let entity_decode s =
  let buf = Buffer.create (String.length s) in
  let n = String.length s in
  let i = ref 0 in
  while !i < n do
    if s.[!i] = '&' then begin
      let window = String.sub s !i (min 12 (n - !i)) in
      match String.index_opt window ';' with
      | Some semi when semi > 1 && semi < 11 ->
        let ent = String.sub s (!i + 1) (semi - 1) in
        let decoded =
          if D_util.starts_with ent "#" then begin
            let num_part = String.sub ent 1 (String.length ent - 1) in
            let cp =
              if D_util.starts_with num_part "x" || D_util.starts_with num_part "X" then
                (try int_of_string ("0x" ^ String.sub num_part 1 (String.length num_part - 1)) with _ -> -1)
              else (try int_of_string num_part with _ -> -1)
            in
            if cp > 0 && cp <= 0x10FFFF then D_rfc2047.utf8_of_cp cp else ""
          end else match String.lowercase_ascii ent with
            | "amp" -> "&" | "lt" -> "<" | "gt" -> ">" | "quot" -> "\""
            | "apos" -> "'" | "nbsp" -> " " | "colon" -> ":" | "sol" -> "/"
            | "period" -> "." | "commat" -> "@" | "num" -> "#"
            | "lpar" -> "(" | "rpar" -> ")" | "excl" -> "!"
            | _ -> ""
        in
        if decoded <> "" then begin
          Buffer.add_string buf decoded; i := !i + semi + 1
        end else (Buffer.add_char buf s.[!i]; incr i)
      | _ -> (Buffer.add_char buf s.[!i]; incr i)
    end else (Buffer.add_char buf s.[!i]; incr i)
  done;
  Buffer.contents buf

(* url scan of a decoded text *)
let scan_text (text : string) (kind : string) : url_info list =
  let results = ref [] in
  let n = String.length text in
  let lower = String.lowercase_ascii text in
  let i = ref 0 in
  while !i < n - 5 do
    let scheme =
      if D_util.starts_with (String.sub lower !i (min 8 (n - !i))) "https://" then Some ("https", 8)
      else if D_util.starts_with (String.sub lower !i (min 7 (n - !i))) "http://" then Some ("http", 7)
      else if D_util.starts_with (String.sub lower !i (min 6 (n - !i))) "ftp://" then Some ("ftp", 6)
      else if D_util.starts_with (String.sub lower !i (min 5 (n - !i))) "data:" then Some ("data", 5)
      else None
    in
    match scheme with
    | None -> incr i
    | Some (sch, skip) ->
      let start = !i in
      let j = ref (!i + skip) in
      let stopset = " \t\n\r<>\"'`)>" in
      while !j < n && not (String.contains stopset text.[!j]) do incr j done;
      let raw0 = String.sub text start (!j - start) in
      (* trim trailing punctuation *)
      let raw =
        let s = raw0 in
        let k = ref (String.length s - 1) in
        while !k >= 0 && (s.[!k] = '.' || s.[!k] = ',' || s.[!k] = ';' ||
                          s.[!k] = '!' || s.[!k] = '?') do decr k done;
        if !k >= 0 then String.sub s 0 (!k + 1) else s
      in
      if raw <> "" then begin
        let after = String.sub raw skip (String.length raw - skip) in
        if sch = "data" then begin
          (* data:[mediatype][;base64],payload *)
          let comma = try Some (String.index after ',') with Not_found -> None in
          match comma with
          | Some ci ->
            let meta = String.lowercase_ascii (String.sub after 0 ci) in
            let payload = String.sub after (ci + 1) (String.length after - ci - 1) in
            let decoded =
              if D_util.contains_ci meta "base64" then
                fst (D_util.b64_decode payload)
              else D_util.qp_decode payload
            in
            let is_html = D_util.contains_ci meta "text/html" in
            let flags = if is_html then ["data_html"] else ["data_uri"] in
            results := { u_raw = D_util.clip 72 raw; u_host = "(data uri)"; u_scheme = "data";
                         u_flags = flags; u_kind = "data"; u_payload = decoded } :: !results
          | None ->
            results := { u_raw = D_util.clip 72 raw; u_host = "(data uri)"; u_scheme = "data";
                         u_flags = ["data_uri"]; u_kind = "data"; u_payload = "" } :: !results
        end else begin
          let authority, pathq =
            match String.index_opt after '/' with
            | Some sl -> String.sub after 0 sl, String.sub after sl (String.length after - sl)
            | None -> after, ""
          in
          let had_userinfo = match String.index_opt authority '@' with Some _ -> true | None -> false in
          let authority = (match String.rindex_opt authority '@' with
              | Some at -> String.sub authority (at + 1) (String.length authority - at - 1)
              | None -> authority) in
          let host, pathq =
            if D_util.starts_with pathq "?" then ("", pathq)
            else match String.index_opt authority '?' with
              | Some q -> (String.sub authority 0 q, "?" ^ String.sub authority (q + 1) (String.length authority - q - 1) ^ pathq)
              | None -> (authority, pathq)
          in
          let path, query =
            match String.index_opt pathq '?' with
            | Some q -> (String.sub pathq 0 q, String.sub pathq q (String.length pathq - q))
            | None -> (pathq, "")
          in
          let host = String.lowercase_ascii host in
          if host <> "" then begin
            let fl = url_flags host path query sch in
            let fl = if had_userinfo then "userinfo" :: fl else fl in
            results := { u_raw = D_util.clip 96 raw; u_host = host; u_scheme = sch;
                         u_flags = fl; u_kind = kind; u_payload = "" } :: !results
          end
        end
      end;
      i := max (!j) (!i + skip)
  done;
  List.rev !results

(* extract href/src attributes from html *)
let scan_html html =
  let n = String.length html in
  let lower = String.lowercase_ascii html in
  let attr_urls = ref [] in
  let i = ref 0 in
  let attrs = ["href="; "src="; "action="] in
  let find_from pos =
    let best = ref None and best_pos = ref n in
    List.iter (fun a ->
      match D_util.find_ci (String.sub lower pos (n - pos)) a with
      | Some k when pos + k < !best_pos -> best := Some a; best_pos := pos + k
      | _ -> ()) attrs;
    match !best with Some a -> Some (!best_pos, a) | None -> None
  in
  (try
  while true do
    match find_from !i with
    | None -> raise Exit
    | Some (k, a) ->
      let eq = k + String.length a - 1 in
      if eq < n && html.[eq] = '=' then begin
        let quote =
          if eq + 1 < n && (html.[eq + 1] = '"' || html.[eq + 1] = '\'') then html.[eq + 1] else ' ' in
        let vstart = if quote = ' ' then eq + 1 else eq + 2 in
        let rec vend j =
          if j >= n then n
          else if quote = ' ' then (if html.[j] = ' ' || html.[j] = '>' || html.[j] = '\n' then j else vend (j + 1))
          else if html.[j] = quote then j else vend (j + 1)
        in
        let ve = vend vstart in
        if vstart < ve then begin
          let v = entity_decode (String.sub html vstart (ve - vstart)) in
          if D_util.starts_with (String.lowercase_ascii v) "http" ||
             D_util.starts_with (String.lowercase_ascii v) "data:" then begin
            let kind = if a = "href=" then "href" else if a = "src=" then "src" else "action" in
            attr_urls := List.append (scan_text v kind) !attr_urls
          end
        end;
        i := ve + 1
      end else i := k + 1
  done
  with Exit -> ());
  let body_urls = scan_text html "body" in
  let all = List.rev !attr_urls @ body_urls in
  let seen = Hashtbl.create 16 in
  List.filter (fun u ->
    if Hashtbl.mem seen u.u_raw then false
    else (Hashtbl.add seen u.u_raw (); true)) all

(* data-uri enrichment: credential form detection inside decoded html payload *)
let enrich_data_uris urls =
  List.map (fun u ->
    if u.u_kind = "data" && u.u_payload <> "" then begin
      let pl = String.lowercase_ascii u.u_payload in
      let has_form = D_util.contains_ci pl "<form" in
      let has_pw = D_util.contains_ci pl "type=\"password\"" || D_util.contains_ci pl "type='password'" ||
                   D_util.contains_ci pl "type=password" in
      let has_remote_action = D_util.contains_ci pl "action=\"http" || D_util.contains_ci pl "action='http" ||
                              D_util.contains_ci pl "action=http" in
      let has_script = D_util.contains_ci pl "<script" in
      let flags = ref u.u_flags in
      if has_form && has_pw then flags := "credential_form" :: !flags;
      if has_form && has_remote_action then flags := "form_remote_action" :: !flags;
      if has_script then flags := "data_script" :: !flags;
      if List.length !flags > List.length u.u_flags then
        { u with u_flags = !flags }
      else u
    end else u) urls

(* tracking pixel: img with 1x1-ish size and remote src *)
let is_tracking_pixel html =
  let n = String.length html in
  let lower = String.lowercase_ascii html in
  let rec go i =
    if i >= n - 20 then false
    else if D_util.starts_with (String.sub lower i (min 4 (n - i))) "<img" then begin
      let stop = try String.index_from lower i '>' with Not_found -> n - 1 in
      let tag = String.sub lower i (stop - i + 1) in
      if (D_util.contains_ci tag "width=\"1\"" || D_util.contains_ci tag "width=1" ||
          D_util.contains_ci tag "width='1'" || D_util.contains_ci tag "height=\"1\"" ||
          D_util.contains_ci tag "height=1" || D_util.contains_ci tag "width:1px" ||
          D_util.contains_ci tag "height:1px") &&
         (D_util.contains_ci tag "src=\"http" || D_util.contains_ci tag "src='http") then true
      else go (stop + 1)
    end else go (i + 1)
  in
  go 0

(* visible text of html *)
let html_text html =
  let buf = Buffer.create (String.length html) in
  let n = String.length html in
  let i = ref 0 in
  let style_depth = ref 0 and script_depth = ref 0 in
  while !i < n do
    if html.[!i] = '<' then begin
      match String.index_opt (String.sub html !i (min 64 (n - !i))) '>' with
      | Some gt ->
        let tag = String.lowercase_ascii (String.sub html (!i + 1) (max 0 (min (gt - 1) 63))) in
        if D_util.starts_with tag "style" then incr style_depth;
        if D_util.starts_with tag "script" then incr script_depth;
        if D_util.starts_with tag "/style" && !style_depth > 0 then decr style_depth;
        if D_util.starts_with tag "/script" && !script_depth > 0 then decr script_depth;
        i := !i + gt + 1
      | None -> (Buffer.add_char buf ' '; incr i)
    end else begin
      if !style_depth = 0 && !script_depth = 0 then Buffer.add_char buf html.[!i];
      incr i
    end
  done;
  entity_decode (Buffer.contents buf)

(* hidden bait text in html *)
let hidden_text_hits html =
  let lower = String.lowercase_ascii html in
  let probes = ["display:none"; "display: none"; "visibility:hidden"; "visibility: hidden";
                "font-size:0"; "font-size: 0"; "text-indent:-9999"; "opacity:0"] in
  List.filter (fun p -> D_util.contains_ci lower p) probes

(* urls found in html: also flag tracking pixel *)
let analyze_html html =
  let urls = enrich_data_uris (scan_html html) in
  let urls =
    if is_tracking_pixel html then
      List.map (fun u ->
        if u.u_kind = "src" && not (List.mem "tracking_pixel" u.u_flags) then
          { u with u_flags = u.u_flags @ ["tracking_pixel"] }
        else u) urls
    else urls
  in
  urls
