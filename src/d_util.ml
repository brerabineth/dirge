(* d_util - shared helpers: text, bytes, color, io *)
let version = "0.1.0"

let no_color_env = try Sys.getenv "NO_COLOR" <> "" with Not_found -> false
let color_flag = ref (not no_color_env)

let red s = if !color_flag then "\027[31m" ^ s ^ "\027[0m" else s
let grn s = if !color_flag then "\027[32m" ^ s ^ "\027[0m" else s
let yel s = if !color_flag then "\027[33m" ^ s ^ "\027[0m" else s
let blu s = if !color_flag then "\027[34m" ^ s ^ "\027[0m" else s
let mag s = if !color_flag then "\027[35m" ^ s ^ "\027[0m" else s
let cya s = if !color_flag then "\027[36m" ^ s ^ "\027[0m" else s
let dim s = if !color_flag then "\027[2m" ^ s ^ "\027[0m" else s
let bold s = if !color_flag then "\027[1m" ^ s ^ "\027[0m" else s

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic; s

let read_stdin_all () =
  let buf = Buffer.create 65536 in
  (try while true do Buffer.add_channel buf stdin 65536 done with End_of_file -> ());
  Buffer.contents buf

let file_exists p = try Sys.file_exists p && not (Sys.is_directory p) with Sys_error _ -> false
let dir_exists p = try Sys.is_directory p with Sys_error _ -> false

(* recursive walk, deterministic order *)
let walk root =
  let acc = ref [] in
  let rec go path depth =
    if depth > 12 then ()
    else if dir_exists path then begin
      let entries = Sys.readdir path in
      Array.sort compare entries;
      Array.iter (fun e ->
        if e <> "." && e <> ".." then go (Filename.concat path e) (depth + 1)) entries
    end else acc := path :: !acc
  in
  go root 0;
  List.rev !acc

(* collect .eml targets from a list of files/dirs *)
let collect_eml targets =
  let acc = ref [] in
  List.iter (fun t ->
    if dir_exists t then
      List.iter (fun f ->
        let ext = String.lowercase_ascii (Filename.extension f) in
        if ext = ".eml" || ext = ".msg" || ext = ".mht" then acc := f :: !acc) (walk t)
    else acc := t :: !acc) targets;
  List.rev !acc

let to_lower s = String.lowercase_ascii s

let contains_ci hay needle =
  let h = String.lowercase_ascii hay and n = String.lowercase_ascii needle in
  let hl = String.length h and nl = String.length n in
  let rec go i =
    if i + nl > hl then false
    else if String.sub h i nl = n then true
    else go (i + 1)
  in
  if nl = 0 then true else go 0

(* index of first case-insensitive match *)
let find_ci hay needle =
  let h = String.lowercase_ascii hay and n = String.lowercase_ascii needle in
  let hl = String.length h and nl = String.length n in
  let rec go i =
    if i + nl > hl then None
    else if String.sub h i nl = n then Some i
    else go (i + 1)
  in
  if nl = 0 then Some 0 else go 0

let count_ci hay needle =
  let h = String.lowercase_ascii hay and n = String.lowercase_ascii needle in
  let hl = String.length h and nl = String.length n in
  let rec go i acc =
    if i + nl > hl then acc
    else if String.sub h i nl = n then go (i + 1) (acc + 1)
    else go (i + 1) acc
  in
  if nl = 0 then 0 else go 0 0

let is_space c = c = ' ' || c = '\t' || c = '\n' || c = '\r'
let trim s =
  let n = String.length s in
  let a = ref 0 and b = ref (n - 1) in
  while !a < n && is_space s.[!a] do incr a done;
  while !b >= !a && is_space s.[!b] do decr b done;
  if n = 0 then "" else String.sub s !a (!b - !a + 1)

let starts_with s pre =
  let pl = String.length pre and sl = String.length s in
  pl <= sl && String.sub s 0 pl = pre

let ends_with s suf =
  let pl = String.length suf and sl = String.length s in
  pl <= sl && String.sub s (sl - pl) pl = suf

let split_char c s =
  String.split_on_char c s

let get_opt l k = try Some (List.assoc k l) with Not_found -> None

let splitlines s =
  let parts = String.split_on_char '\n' s in
  List.map (fun p ->
    let n = String.length p in
    if n > 0 && p.[n - 1] = '\r' then String.sub p 0 (n - 1) else p) parts

let join_lines = String.concat "\n"

(* UTF-8: count codepoints and clip safely *)
let utf8_len c =
  if Char.code c < 0x80 then 1
  else if Char.code c land 0xE0 = 0xC0 then 2
  else if Char.code c land 0xF0 = 0xE0 then 3
  else if Char.code c land 0xF8 = 0xF0 then 4
  else 1 (* invalid byte, treat as 1 *)

let utf8_next s i =
  let n = String.length s in
  if i >= n then n
  else
    let l = utf8_len s.[i] in
    min (i + l) n

(* decode one codepoint at i; returns (cp, next_index); invalid -> (0xFFFD, i+1) *)
let utf8_cp s i =
  let n = String.length s in
  if i >= n then (-1, n)
  else
    let b0 = Char.code s.[i] in
    if b0 < 0x80 then (b0, i + 1)
    else if b0 land 0xE0 = 0xC0 && i + 1 < n then
      ((b0 land 0x1F) lsl 6 lor (Char.code s.[i+1] land 0x3F), i + 2)
    else if b0 land 0xF0 = 0xE0 && i + 2 < n then
      ((b0 land 0x0F) lsl 12 lor (Char.code s.[i+1] land 0x3F) lsl 6
        lor (Char.code s.[i+2] land 0x3F), i + 3)
    else if b0 land 0xF8 = 0xF0 && i + 3 < n then
      ((b0 land 0x07) lsl 18 lor (Char.code s.[i+1] land 0x3F) lsl 12
        lor (Char.code s.[i+2] land 0x3F) lsl 6 lor (Char.code s.[i+3] land 0x3F), i + 4)
    else (0xFFFD, i + 1)

let cp_count s =
  let n = String.length s in
  let rec go i acc = if i >= n then acc else go (utf8_next s i) (acc + 1) in
  go 0 0

(* clip to max display cells (cp-count based), ellipsis if cut *)
let clip max_len s =
  if cp_count s <= max_len then s
  else
    let buf = Buffer.create (max_len * 2) in
    let rec go i k =
      if k >= max_len - 1 || i >= String.length s then ()
      else
        let nxt = utf8_next s i in
        Buffer.add_substring buf s i (nxt - i);
        go nxt (k + 1)
    in
    go 0 0;
    Buffer.contents buf ^ "…"

(* mask credential shapes in evidence lines *)
let mask_secrets s =
  let re_shape prefix data =
    let n = String.length data in
    let pre_l = String.length prefix in
    let buf = Buffer.create n in
    let i = ref 0 in
    while !i < n do
      if !i + pre_l <= n && String.lowercase_ascii (String.sub data !i pre_l) = String.lowercase_ascii prefix then begin
        let j = ref (!i + pre_l) in
        while !j < n &&
              let c = data.[!j] in
              (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c = '_' || c = '-' do incr j done;
        if !j - !i >= pre_l + 8 then begin
          Buffer.add_string buf (String.sub data !i pre_l);
          Buffer.add_string buf "[REDACTED]";
          i := !j
        end else begin
          Buffer.add_char buf data.[!i]; incr i
        end
      end else begin
        Buffer.add_char buf data.[!i]; incr i
      end
    done;
    Buffer.contents buf
  in
  s |> re_shape "sk-" |> re_shape "ghp_" |> re_shape "github_pat_"
    |> re_shape "xoxb-" |> re_shape "AKIA"

(* defang a URL for safe display *)
let defang u =
  let s = ref u in
  let rep old new_ =
    match find_ci !s old with
    | Some i ->
      let b = Buffer.create (String.length !s + 4) in
      Buffer.add_substring b !s 0 i;
      Buffer.add_string b new_;
      Buffer.add_substring b !s (i + String.length old) (String.length !s - i - String.length old);
      s := Buffer.contents b
    | None -> ()
  in
  rep "https://" "hxxps://";
  rep "http://" "hxxp://";
  rep "ftp://" "fxp://";
  !s

(* defang dots in a host only *)
let defang_host h =
  let buf = Buffer.create (String.length h + 8) in
  String.iter (fun c -> if c = '.' then Buffer.add_string buf "[.]" else Buffer.add_char buf c) h;
  Buffer.contents buf

(* bounded levenshtein *)
let levenshtein a b =
  let la = String.length a and lb = String.length b in
  if abs (la - lb) > 3 then 99
  else begin
    let prev = Array.init (lb + 1) (fun i -> i) in
    for i = 1 to la do
      let cur = Array.make (lb + 1) 0 in
      cur.(0) <- i;
      for j = 1 to lb do
        let cost = if a.[i - 1] = b.[j - 1] then 0 else 1 in
        cur.(j) <- min (prev.(j) + 1) (min (cur.(j - 1) + 1) (prev.(j - 1) + cost))
      done;
      Array.blit cur 0 prev 0 (lb + 1)
    done;
    prev.(lb)
  end

(* crc32 for the zip fixture writer *)
let crc32_table = lazy (
  let t = Array.make 256 0l in
  for i = 0 to 255 do
    let c = ref (Int32.of_int i) in
    for _ = 0 to 7 do
      if Int32.logand !c 1l <> 0l then c := Int32.logxor (Int32.shift_right_logical !c 1) 0xEDB88320l
      else c := Int32.shift_right_logical !c 1
    done;
    t.(i) <- !c
  done;
  t)

let crc32 data =
  let t = Lazy.force crc32_table in
  let c = ref 0xFFFFFFFFl in
  String.iter (fun ch ->
    let idx = Int32.to_int (Int32.logand (Int32.logxor !c (Int32.of_int (Char.code ch))) 0xFFl) in
    c := Int32.logxor t.(idx) (Int32.shift_right_logical !c 8)) data;
  Int32.logxor !c 0xFFFFFFFFl

(* base64 decode, permissive: skips whitespace, keeps invalid as '?' *)
let b64_decode s =
  let tbl = Hashtbl.create 64 in
  let alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" in
  String.iteri (fun i c -> Hashtbl.replace tbl c i) alpha;
  let buf = Buffer.create (String.length s / 4 * 3) in
  let acc = ref 0 and bits = ref 0 and bad = ref 0 in
  String.iter (fun c ->
    if c = '=' || is_space c then ()
    else match Hashtbl.find_opt tbl c with
      | Some v when (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c = '+' || c = '/' ->
        acc := (!acc lsl 6) lor v; bits := !bits + 6;
        if !bits = 6 * 4 then begin
          Buffer.add_char buf (Char.chr ((!acc lsr 16) land 0xFF));
          Buffer.add_char buf (Char.chr ((!acc lsr 8) land 0xFF));
          Buffer.add_char buf (Char.chr (!acc land 0xFF));
          acc := 0; bits := 0
        end
      | _ -> incr bad) s;
  (* flush remaining bits *)
  (match !bits with
   | 12 -> Buffer.add_char buf (Char.chr ((!acc lsr 4) land 0xFF))
   | 18 -> Buffer.add_char buf (Char.chr ((!acc lsr 10) land 0xFF));
           Buffer.add_char buf (Char.chr ((!acc lsr 2) land 0xFF))
   | _ -> ());
  (Buffer.contents buf, !bad)

let is_b64_char c =
  (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
  || c = '+' || c = '/' || c = '=' || is_space c

(* longest run of consecutive base64 chars *)
let longest_b64_run s =
  let n = String.length s in
  let best = ref 0 and cur = ref 0 in
  for i = 0 to n - 1 do
    if is_b64_char s.[i] then (incr cur; if !cur > !best then best := !cur)
    else cur := 0
  done;
  !best

(* quoted-printable decode *)
let qp_decode s =
  let n = String.length s in
  let buf = Buffer.create n in
  let i = ref 0 in
  let hex c =
    match c with
    | '0'..'9' -> Some (Char.code c - Char.code '0')
    | 'a'..'f' -> Some (Char.code c - Char.code 'a' + 10)
    | 'A'..'F' -> Some (Char.code c - Char.code 'A' + 10)
    | _ -> None
  in
  while !i < n do
    let c = s.[!i] in
    if c = '=' then begin
      if !i + 2 < n && s.[!i + 1] = '\r' && s.[!i + 2] = '\n' then i := !i + 3
      else if !i + 1 < n && s.[!i + 1] = '\n' then i := !i + 2
      else if !i + 2 < n && hex s.[!i + 1] <> None && hex s.[!i + 2] <> None then begin
        Buffer.add_char buf (Char.chr ((Option.get (hex s.[!i + 1])) * 16 + Option.get (hex s.[!i + 2])));
        i := !i + 3
      end else begin
        Buffer.add_char buf '='; incr i
      end
    end else begin
      Buffer.add_char buf c; incr i
    end
  done;
  Buffer.contents buf

let qp_encode s =
  let n = String.length s in
  let buf = Buffer.create n in
  String.iter (fun c ->
    let k = Char.code c in
    if c = '\n' || (k >= 33 && k <= 126 && c <> '=') then Buffer.add_char buf c
    else Printf.bprintf buf "=%02X" k) s;
  Buffer.contents buf

let hex_of_int64 w width =
  Printf.sprintf "%0*Lx" width w

(* brand catalog: (token, legit domains) - used by url/headers rules *)
let brands : (string * string list) list = [
  ("paypal", ["paypal.com"]);
  ("microsoft", ["microsoft.com"; "outlook.com"; "office.com"; "live.com"; "microsoftonline.com"]);
  ("outlook", ["outlook.com"; "microsoft.com"; "office.com"]);
  ("office365", ["office.com"; "microsoftonline.com"; "microsoft.com"]);
  ("apple", ["apple.com"; "icloud.com"]);
  ("icloud", ["icloud.com"; "apple.com"]);
  ("google", ["google.com"; "gmail.com"; "accounts.google.com"]);
  ("gmail", ["gmail.com"; "google.com"]);
  ("amazon", ["amazon.com"; "aws.amazon.com"]);
  ("netflix", ["netflix.com"]);
  ("facebook", ["facebook.com"; "meta.com"]);
  ("instagram", ["instagram.com"]);
  ("whatsapp", ["whatsapp.com"]);
  ("linkedin", ["linkedin.com"]);
  ("dhl", ["dhl.com"; "dhl.de"]);
  ("fedex", ["fedex.com"]);
  ("ups", ["ups.com"]);
  ("usps", ["usps.com"]);
  ("hsbc", ["hsbc.com"]);
  ("chase", ["chase.com"]);
  ("wellsfargo", ["wellsfargo.com"]);
  ("citibank", ["citi.com"; "citibank.com"]);
  ("santander", ["santander.com"]);
  ("binance", ["binance.com"]);
  ("coinbase", ["coinbase.com"]);
  ("metamask", ["metamask.io"]);
  ("steam", ["steampowered.com"; "steamcommunity.com"]);
  ("dropbox", ["dropbox.com"]);
  ("adobe", ["adobe.com"]);
  ("zoom", ["zoom.us"]);
  ("slack", ["slack.com"]);
  ("docusign", ["docusign.com"; "docusign.net"]);
  ("revolut", ["revolut.com"]);
  ("wise", ["wise.com"]);
  ("starling", ["starlingbank.com"]);
  ("monzo", ["monzo.com"]);
]

let registrable host =
  match String.split_on_char '.' host |> List.filter (fun x -> x <> "") with
  | lbls when List.length lbls >= 2 ->
    let n = List.length lbls in
    let two = List.filteri (fun i _ -> i >= n - 2) lbls in
    String.concat "." two
  | lbls -> String.concat "." lbls

let banner =
"                          ,   ,$$s.
                       ,$$$s,s$$$$$s.
   _____             .s$$$$$$$$$$$$$'
  |     | .-----. .--| |----.---.-.-----.
  |  |  ||  _  ||  _  ||   _|  _  |  _  |
  |____  ||_____||_____||__| |_____|_____|
  |:  1  |                        the mail autopsy
  |::.. . |
  `-------'"

let sep = "  ------------------------------------------------------------------"

(* suspicious unicode classes in text: returns (class_name, count) list *)
let suspicious_unicode s =
  let bidi = ref 0 and zero = ref 0 and tags = ref 0 and vsel = ref 0 in
  let n = String.length s in
  let i = ref 0 in
  while !i < n do
    let cp, nxt = utf8_cp s !i in
    (if (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069) then incr bidi
     else if (cp >= 0x200B && cp <= 0x200F) || (cp >= 0x2060 && cp <= 0x2064)
          || cp = 0x00AD || cp = 0xFEFF then incr zero
     else if cp >= 0xE0000 && cp <= 0xE007F then incr tags
     else if (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0x180B && cp <= 0x180F) then incr vsel);
    i := nxt
  done;
  [ "bidi_control", !bidi; "zero_width", !zero; "unicode_tags", !tags; "variation_selectors", !vsel ]
  |> List.filter (fun (_, c) -> c > 0)

(* strip invisible/suspicious unicode for safe evidence display *)
let strip_invisible s =
  let buf = Buffer.create (String.length s) in
  let n = String.length s in
  let i = ref 0 in
  while !i < n do
    let cp, nxt = utf8_cp s !i in
    let drop =
      (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)
      || (cp >= 0x200B && cp <= 0x200F) || cp = 0x00AD
      || cp = 0xFEFF || (cp >= 0xE0000 && cp <= 0xE007F)
      || (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0x180B && cp <= 0x180F)
      || (cp < 0x20 && cp <> 10) || cp = 0x7F
    in
    if not drop then begin
      let chunk_len = nxt - !i in
      if chunk_len > 0 && !i + chunk_len <= n then
        Buffer.add_substring buf s !i chunk_len
    end;
    i := nxt
  done;
  Buffer.contents buf
