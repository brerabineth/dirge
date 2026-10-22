(* d_mime - RFC5322 header block + MIME multipart tree, permissive offline parser *)

type part = {
  p_headers : (string * string) list;  (* lowercased names, unfolded values, in order *)
  p_type : string;                     (* "text" *)
  p_subtype : string;                  (* "plain" *)
  p_params : (string * string) list;
  p_encoding : string;
  p_disposition : string option;       (* "attachment" | "inline" *)
  p_disp_params : (string * string) list;
  p_body_raw : string;
  p_body_decoded : string;
  p_children : part list;
  p_nested : part option;              (* message/rfc822 *)
  p_is_mp : bool;
}

let parse_warnings : string list ref = ref []
let warn w =
  if not (List.mem w !parse_warnings) then parse_warnings := w :: !parse_warnings
let reset_warn () = parse_warnings := []

let normalize_crlf s =
  let buf = Buffer.create (String.length s) in
  let n = String.length s in
  let i = ref 0 in
  while !i < n do
    if s.[!i] = '\r' then begin
      if !i + 1 < n && s.[!i + 1] = '\n' then (Buffer.add_char buf '\n'; i := !i + 2)
      else (Buffer.add_char buf '\n'; incr i)
    end else begin
      Buffer.add_char buf s.[!i]; incr i
    end
  done;
  Buffer.contents buf

(* split header block from body; returns headers (raw, folded) + body + found flag *)
let split_headers s =
  let lines = Array.of_list (D_util.splitlines s) in
  let n = Array.length lines in
  let i = ref 0 in
  (* skip leading blank lines *)
  while !i < n && D_util.trim lines.(!i) = "" do incr i done;
  let raw = ref [] in
  let cur = Buffer.create 256 in
  let started = ref false in
  let done_hdrs = ref false in
  while not !done_hdrs && !i < n do
    let l = lines.(!i) in
    if D_util.trim l = "" then done_hdrs := true
    else if (String.length l > 0 && (l.[0] = ' ' || l.[0] = '\t')) && !started then begin
      Buffer.add_char cur '\n'; Buffer.add_string cur (D_util.trim l); incr i
    end else begin
      if !started then begin
        raw := Buffer.contents cur :: !raw; Buffer.clear cur
      end;
      (* is this a header line at all? name: value *)
      match String.index_opt l ':' with
      | Some _ -> Buffer.add_string cur l; started := true; incr i
      | None -> done_hdrs := true (* garbage: body without headers *)
    end
  done;
  if !started then raw := Buffer.contents cur :: !raw;
  let hdrs =
    List.rev_map (fun raw_l ->
      match String.index_opt raw_l ':' with
      | Some c ->
        let name = String.sub raw_l 0 c in
        let value = String.sub raw_l (c + 1) (String.length raw_l - c - 1) in
        (D_util.trim (String.lowercase_ascii name), D_util.trim value)
      | None -> (D_util.trim raw_l, "")) !raw
  in
  let body =
    if !i < n then
      String.concat "\n" (Array.to_list (Array.sub lines (!i + 1) (n - !i - 1)))
    else ""
  in
  (hdrs, body)

let hdr hdrs name =
  let rec go = function
    | [] -> None
    | (k, v) :: rest -> if k = name then Some v else go rest
  in
  go hdrs

let hdr_all hdrs name =
  List.filter_map (fun (k, v) -> if k = name then Some v else None) hdrs

(* parse content-type or disposition value: type/sub; k=v; k2=v2 ; kstar=... *)
let parse_params value =
  match String.index_opt value ';' with
  | None -> (D_util.trim value, [])
  | Some semi ->
    let main = D_util.trim (String.sub value 0 semi) in
    let rest = String.sub value (semi + 1) (String.length value - semi - 1) in
    let params = ref [] in
    (* split on ';' not inside quotes *)
    let n = String.length rest in
    let item = Buffer.create 64 in
    let inq = ref false in
    let items = ref [] in
    for i = 0 to n - 1 do
      let c = rest.[i] in
      if c = '"' then (inq := not !inq; Buffer.add_char item c)
      else if c = ';' && not !inq then (items := Buffer.contents item :: !items; Buffer.clear item)
      else Buffer.add_char item c
    done;
    items := Buffer.contents item :: !items;
    List.iter (fun it ->
      let it = D_util.trim it in
      match String.index_opt it '=' with
      | Some eq ->
        let k = D_util.trim (String.lowercase_ascii (String.sub it 0 eq)) in
        let v = D_util.trim (String.sub it (eq + 1) (String.length it - eq - 1)) in
        let v =
          if String.length v >= 2 && v.[0] = '"' && v.[String.length v - 1] = '"' then
            String.sub v 1 (String.length v - 2)
          else v
        in
        if k <> "" then params := (k, v) :: !params
      | None -> ()) !items;
    (main, List.rev !params)

(* rfc2231: filename*=UTF-8''in%20voice ; filename*0*=..;filename*1=.. *)
let resolve_extended params =
  let simple = List.filter (fun (k, _) -> k = "" || not (D_util.contains_ci k "*")) params in
  let ext = List.filter (fun (k, _) -> k <> "" && D_util.contains_ci k "*") params in
  let get k = try Some (List.assoc k params) with Not_found -> None in
  let base_of k =
    match String.index_opt k '*' with
    | Some st when st > 0 -> Some (String.sub k 0 st)
    | _ -> None
  in
  let percent_decode s =
    let buf = Buffer.create (String.length s) in
    let n = String.length s and i = ref 0 in
    while !i < n do
      if s.[!i] = '%' && !i + 2 < n then begin
        let h = D_rfc2047.hex s.[!i + 1] and l = D_rfc2047.hex s.[!i + 2] in
        if h >= 0 && l >= 0 then begin
          Buffer.add_char buf (Char.chr (h * 16 + l)); i := !i + 3
        end else (Buffer.add_char buf s.[!i]; incr i)
      end else (Buffer.add_char buf s.[!i]; incr i)
    done;
    Buffer.contents buf
  in
  let decode_ext v =
    (* charset'lang'value *)
    match String.index_opt v '\'' with
    | None -> v
    | Some a ->
      let rest = String.sub v (a + 1) (String.length v - a - 1) in
      match String.index_opt rest '\'' with
      | None -> v
      | Some b ->
        let cs = String.sub v 0 a in
        D_rfc2047.to_utf8 cs (percent_decode (String.sub rest (b + 1) (String.length rest - b - 1)))
  in
  let bases = List.filter_map (fun (k, _) -> base_of k) ext |> List.sort_uniq compare in
  let resolved =
    List.filter_map (fun b ->
      (* merge numbered continuations *)
      let rec merge idx acc =
        let kstar = Printf.sprintf "%s*%d*" b idx and kplain = Printf.sprintf "%s*%d" b idx in
        match get kstar, get kplain with
        | Some v, _ -> merge (idx + 1) (acc ^ "\u{0001}" ^ v)
        | None, Some v -> merge (idx + 1) (acc ^ "\u{0001}" ^ v)
        | None, None -> acc
      in
      let merged = merge 0 "" in
      if merged <> "" then begin
        let pieces = String.split_on_char (Char.chr 1) merged |> List.filter (fun x -> x <> "") in
        (match pieces with
         | first :: rest ->
           let encoded = List.length (String.split_on_char '\'' first) >= 3 in
           let v = List.fold_left (^) "" (List.map (fun p -> if encoded then percent_decode p else p) pieces) in
           let v = if encoded then (match String.index_opt v '\'' with
             | Some a -> (match String.index_opt (String.sub v (a + 1) (String.length v - a - 1)) '\'' with
               | Some b2 -> String.sub v (a + 1 + b2 + 1) (String.length v - a - b2 - 2)
               | None -> v)
             | None -> v) else v in
           let v = if encoded then D_rfc2047.to_utf8 "utf-8" v else v in
           ignore rest;
           Some (b, v)
         | [] -> None)
      end else match get (b ^ "*") with
        | Some v -> Some (b, decode_ext v)
        | None -> None) bases
  in
  simple @ resolved

let decode_body encoding raw =
  let enc = String.lowercase_ascii (D_util.trim encoding) in
  match enc with
  | "base64" ->
    let cleaned = Buffer.create (String.length raw) in
    String.iter (fun c -> if not (D_util.is_space c) then Buffer.add_char cleaned c) raw;
    let s = Buffer.contents cleaned in
    (* count '=' padding as fine; strip trailing '=' before decode is handled inside *)
    let decoded, _bad = D_util.b64_decode s in
    decoded
  | "quoted-printable" -> D_util.qp_decode raw
  | _ -> raw

let split_on_boundary body boundary =
  let delim = "--" ^ boundary in
  let lines = Array.of_list (D_util.splitlines body) in
  let n = Array.length lines in
  let chunks = ref [] in
  let cur = ref [] in
  let started = ref false in
  let closed = ref false in
  for i = 0 to n - 1 do
    let l = lines.(i) in
    let lt = D_util.trim l in
    if lt = delim then begin
      if !started then chunks := List.rev !cur :: !chunks;
      cur := []; started := true
    end else if lt = delim ^ "--" then begin
      if !started then chunks := List.rev !cur :: !chunks;
      cur := []; started := false; closed := true
    end else if !started then cur := l :: !cur
  done;
  if !started then chunks := List.rev !cur :: !chunks;
  let parts_raw = List.rev !chunks in
  (* drop one trailing empty line per chunk (left by the boundary newline) *)
  let trim_chunk c =
    match List.rev c with
    | "" :: rest -> List.rev rest
    | _ -> c
  in
  let parts_raw = List.map trim_chunk parts_raw in
  let mk chunk =
    String.concat "\n" chunk ^ "\n"
  in
  List.map mk parts_raw, !closed

let rec make_part hdrs body =
  let ct = match hdr hdrs "content-type" with Some v -> v | None -> "text/plain" in
  let main, params = parse_params ct in
  let (ptype, psub) =
    match String.index_opt main '/' with
    | Some sl -> (String.lowercase_ascii (D_util.trim (String.sub main 0 sl)),
                  String.lowercase_ascii (D_util.trim (String.sub main (sl + 1) (String.length main - sl - 1))))
    | None ->
      if main = "" then ("text", "plain")
      else (String.lowercase_ascii main, "")
  in
  let enc = match hdr hdrs "content-transfer-encoding" with Some v -> v | None -> "7bit" in
  let disp, dparams =
    match hdr hdrs "content-disposition" with
    | Some v -> let m, p = parse_params v in (Some (String.lowercase_ascii m), p)
    | None -> (None, [])
  in
  let params = resolve_extended params in
  let dparams = resolve_extended dparams in
  if ptype = "multipart" then begin
    let boundary = try Some (List.assoc "boundary" params) with Not_found -> None in
    match boundary with
    | None ->
      warn "multipart without boundary treated as text";
      let decoded = decode_body enc body in
      { p_headers = hdrs; p_type = ptype; p_subtype = psub; p_params = params;
        p_encoding = enc; p_disposition = disp; p_disp_params = dparams;
        p_body_raw = body; p_body_decoded = decoded; p_children = []; p_nested = None; p_is_mp = false }
    | Some b ->
      let chunks, closed = split_on_boundary body b in
      if not closed then warn "multipart not closed with final boundary";
      if chunks = [] then warn "multipart with zero parts";
      let children = List.map (fun c -> let h, b2 = split_headers c in make_part h b2) chunks in
      { p_headers = hdrs; p_type = ptype; p_subtype = psub; p_params = params;
        p_encoding = enc; p_disposition = disp; p_disp_params = dparams;
        p_body_raw = body; p_body_decoded = ""; p_children = children; p_nested = None; p_is_mp = true }
  end else if ptype = "message" && (psub = "rfc822" || psub = "global") then begin
    let h2, b2 = split_headers (decode_body enc body) in
    let inner = make_part h2 b2 in
    { p_headers = hdrs; p_type = ptype; p_subtype = psub; p_params = params;
      p_encoding = enc; p_disposition = disp; p_disp_params = dparams;
      p_body_raw = body; p_body_decoded = ""; p_children = []; p_nested = Some inner; p_is_mp = false }
  end else begin
    let decoded = decode_body enc body in
    { p_headers = hdrs; p_type = ptype; p_subtype = psub; p_params = params;
      p_encoding = enc; p_disposition = disp; p_disp_params = dparams;
      p_body_raw = body; p_body_decoded = decoded; p_children = []; p_nested = None; p_is_mp = false }
  end

let parse raw =
  let s = normalize_crlf raw in
  let hdrs, body = split_headers s in
  make_part hdrs body

let rec flatten p =
  let inner = match p.p_nested with Some n -> flatten n | None -> [] in
  List.concat [ if p.p_is_mp then List.concat_map flatten p.p_children else [p]; inner ]

let has_filename p =
  match D_util.get_opt p.p_disp_params "filename" with
  | Some _ -> true
  | None ->
    (match D_util.get_opt p.p_params "name" with
     | Some _ -> true
     | None -> false)

let filename_of p =
  match D_util.get_opt p.p_disp_params "filename" with
  | Some f -> Some f
  | None -> D_util.get_opt p.p_params "name"

let is_attachment p =
  (match p.p_disposition with Some d -> d = "attachment" | None -> false)
  || (has_filename p && not (p.p_type = "text" && (p.p_subtype = "plain" || p.p_subtype = "html")))

(* first text/plain else text/html else empty *)
let best_text p =
  let leaves = flatten p in
  let t = List.find_opt (fun x -> x.p_type = "text" && x.p_subtype = "plain") leaves in
  match t with
  | Some x -> (x.p_body_decoded, true)
  | None ->
    let h = List.find_opt (fun x -> x.p_type = "text" && x.p_subtype = "html") leaves in
    (match h with
     | Some x -> (x.p_body_decoded, false)
     | None -> ("", false))

let html_parts p =
  List.filter (fun x -> x.p_type = "text" && x.p_subtype = "html") (flatten p)

let attachments p =
  List.filter is_attachment (flatten p)
