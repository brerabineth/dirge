(* d_rfc2047 - encoded-word decoding for headers *)
let unknown_charsets : string list ref = ref []
let record_unknown cs =
  let cs = String.lowercase_ascii cs in
  if not (List.exists (fun x -> x = cs) !unknown_charsets) then
    unknown_charsets := cs :: !unknown_charsets
let reset_unknown () = unknown_charsets := []

let utf8_of_cp cp =
  let buf = Buffer.create 4 in
  if cp < 0x80 then Buffer.add_char buf (Char.chr cp)
  else if cp < 0x800 then begin
    Buffer.add_char buf (Char.chr (0xC0 lor (cp lsr 6)));
    Buffer.add_char buf (Char.chr (0x80 lor (cp land 0x3F)))
  end else if cp < 0x10000 then begin
    Buffer.add_char buf (Char.chr (0xE0 lor (cp lsr 12)));
    Buffer.add_char buf (Char.chr (0x80 lor ((cp lsr 6) land 0x3F)));
    Buffer.add_char buf (Char.chr (0x80 lor (cp land 0x3F)))
  end else begin
    Buffer.add_char buf (Char.chr (0xF0 lor (cp lsr 18)));
    Buffer.add_char buf (Char.chr (0x80 lor ((cp lsr 12) land 0x3F)));
    Buffer.add_char buf (Char.chr (0x80 lor ((cp lsr 6) land 0x3F)));
    Buffer.add_char buf (Char.chr (0x80 lor (cp land 0x3F)))
  end;
  Buffer.contents buf

(* charset -> utf8 for single-byte charsets; unknown pass through + record *)
let to_utf8 cs bytes =
  let cs = String.lowercase_ascii cs in
  let ascii = (cs = "us-ascii" || cs = "ascii" || cs = "iso-ir-6") in
  if cs = "utf-8" || cs = "utf8" || cs = "utf8mb4" || ascii then bytes
  else if cs = "iso-8859-1" || cs = "latin1" || cs = "iso8859-1" || cs = "iso_8859-1"
       || cs = "windows-1252" || cs = "cp1252" then begin
    let cp1252 = (cs = "windows-1252" || cs = "cp1252") in
    let extras = [| 0x20AC; 0xFFFD; 0x201A; 0x0192; 0x201E; 0x2026; 0x2020; 0x2021;
                    0x02C6; 0x2030; 0x0160; 0x2039; 0x0152; 0xFFFD; 0x017D; 0xFFFD;
                    0xFFFD; 0x2018; 0x2019; 0x201C; 0x201D; 0x2022; 0x2013; 0x2014;
                    0x02DC; 0x2122; 0x0161; 0x203A; 0x0153; 0xFFFD; 0x017E; 0x0178 |] in
    let buf = Buffer.create (String.length bytes * 2) in
    String.iter (fun c ->
      let k = Char.code c in
      if k < 0x80 then Buffer.add_char buf c
      else if k >= 0xA0 then Buffer.add_string buf (utf8_of_cp k)
      else if cp1252 then begin
        let cp = extras.(k - 0x80) in
        if cp <> 0xFFFD then Buffer.add_string buf (utf8_of_cp cp)
        else Buffer.add_string buf "\u{FFFD}"
      end else Buffer.add_string buf "\u{FFFD}") bytes;
    Buffer.contents buf
  end else begin
    record_unknown cs; bytes
  end

let hex c =
  match c with
  | '0'..'9' -> Char.code c - Char.code '0'
  | 'a'..'f' -> Char.code c - Char.code 'a' + 10
  | 'A'..'F' -> Char.code c - Char.code 'A' + 10
  | _ -> -1

(* Q encodes _ as space *)
let q_decode s =
  let n = String.length s in
  let buf = Buffer.create n in
  let i = ref 0 in
  while !i < n do
    let c = s.[!i] in
    if c = '_' then (Buffer.add_char buf ' '; incr i)
    else if c = '=' && !i + 2 < n && hex s.[!i + 1] >= 0 && hex s.[!i + 2] >= 0 then begin
      Buffer.add_char buf (Char.chr (hex s.[!i + 1] * 16 + hex s.[!i + 2]));
      i := !i + 3
    end else (Buffer.add_char buf c; incr i)
  done;
  Buffer.contents buf

(* decode all =?cs?enc?payload?= words in a header value *)
let decode value =
  let n = String.length value in
  let buf = Buffer.create n in
  let i = ref 0 in
  let last_was_ew = ref false in
  let pending_ws = ref 0 in
  while !i < n do
    if value.[!i] = '=' && !i + 1 < n && value.[!i + 1] = '?' then begin
      (* scan for second '?' within a sane window *)
      let limit = min (n - !i) 512 in
      let sub = String.sub value !i limit in
      match String.index_opt (String.sub sub 2 (limit - 2)) '?' with
      | Some q1 when q1 > 0 ->
        let cs = String.sub sub 2 q1 in
        let enc_pos = !i + 2 + q1 + 1 in
        if enc_pos + 2 < n && value.[!i + 2 + q1 + 1 + 1] = '?' then begin
          let enc = Char.lowercase_ascii value.[enc_pos] in
          if value.[enc_pos + 1] = '?' then begin
            let rec find_end j =
              if j + 1 >= n then None
              else if value.[j] = '?' && value.[j + 1] = '=' then Some j
              else find_end (j + 1)
            in
            match find_end (enc_pos + 1) with
            | Some j ->
              let payload = String.sub value (enc_pos + 2) (j - enc_pos - 2) in
              let decoded = (if enc = 'b' then fst (D_util.b64_decode payload) else q_decode payload) in
              let out = to_utf8 cs decoded in
              if !last_was_ew && !pending_ws > 0 then ()
              else if !pending_ws > 0 then Buffer.add_string buf (String.make !pending_ws ' ');
              Buffer.add_string buf out;
              pending_ws := 0;
              last_was_ew := true;
              i := j + 2
            | None -> Buffer.add_char buf value.[!i]; incr i; last_was_ew := false
          end else begin
            Buffer.add_char buf value.[!i]; incr i; last_was_ew := false
          end
        end else begin
          Buffer.add_char buf value.[!i]; incr i; last_was_ew := false
        end
      | _ -> Buffer.add_char buf value.[!i]; incr i; last_was_ew := false
    end else begin
      let c = value.[!i] in
      if c = ' ' || c = '\t' then pending_ws := !pending_ws + 1
      else begin
        if !pending_ws > 0 then Buffer.add_string buf (String.make !pending_ws ' ');
        pending_ws := 0;
        last_was_ew := false;
        Buffer.add_char buf c
      end;
      incr i
    end
  done;
  if !pending_ws > 0 then Buffer.add_string buf (String.make !pending_ws ' ');
  Buffer.contents buf
