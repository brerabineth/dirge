(* d_attach - attachment risk: filenames, archives (zip walk), pdf, html, rtf *)

type att_info = {
  at_name : string;
  at_type : string;
  at_size : int;
  at_flags : string list;
  at_entries : string list;  (* zip central-dir entry names, if archive *)
}

let risky_exts = [
  ".exe"; ".scr"; ".com"; ".pif"; ".cpl"; ".msi"; ".bat"; ".cmd"; ".ps1";
  ".js"; ".jse"; ".vbs"; ".vbe"; ".wsf"; ".wsh"; ".hta"; ".jar"; ".lnk"
]

let doc_exts = [".pdf"; ".doc"; ".docx"; ".xls"; ".xlsx"; ".ppt"; ".pptx"; ".rtf"; ".jpg"; ".png"]
let disk_exts = [".iso"; ".img"; ".vhd"; ".vhdx"]
let exec_click_exts = [".exe"; ".scr"; ".lnk"; ".js"; ".hta"; ".vbs"; ".bat"; ".cmd"; ".com"; ".pif"]
let macro_exts = [".docm"; ".xlsm"; ".pptm"]

let macro_markers = [
  "word/vbaproject.bin"; "xl/vbaproject.bin"; "ppt/vbaproject.bin";
  "vbaProject.bin"; "vbaProject"
]

let pyc_exts = [".pyc"; ".pyo"]

let exts_of s =
  (* ordered earliest-first, e.g. "a.pdf.exe" -> [".pdf"; ".exe"] *)
  let rec go acc s =
    match String.rindex_opt s '.' with
    | Some i when i > 0 ->
      go (String.sub s i (String.length s - i) :: acc) (String.sub s 0 i)
    | _ -> acc
  in
  go [] s

let zip_entries bytes =
  let n = String.length bytes in
  let entries = ref [] in
  let i = ref 0 in
  while !i + 46 <= n do
    if bytes.[!i] = 'P' && bytes.[!i + 1] = 'K' && bytes.[!i + 2] = Char.chr 1 && bytes.[!i + 3] = Char.chr 2 then begin
      let name_len = Char.code bytes.[!i + 28] lor (Char.code bytes.[!i + 29] lsl 8) in
      if name_len > 0 && !i + 46 + name_len <= n then begin
        entries := String.sub bytes (!i + 46) name_len :: !entries;
        i := !i + 46 + name_len
      end else i := !i + 4
    end else i := !i + 1
  done;
  List.rev !entries

let is_zip bytes = String.length bytes >= 4 && bytes.[0] = 'P' && bytes.[1] = 'K' &&
                   Char.code bytes.[2] = 3 && Char.code bytes.[3] = 4

let pdf_flags bytes =
  let flags = ref [] in
  if String.length bytes >= 5 && String.sub bytes 0 5 = "%PDF-" then begin
    let probes = [
      "/OpenAction", "pdf_openaction";
      "/AA", "pdf_aa";
      "/JavaScript", "pdf_javascript";
      "/Launch", "pdf_launch";
      "/EmbeddedFile", "pdf_embedded";
      "/URI", "pdf_uri";
      "/GoToR", "pdf_gotor";
      "/RichMedia", "pdf_richmedia";
    ] in
    List.iter (fun (probe, flag) ->
      if D_util.contains_ci bytes probe then flags := flag :: !flags) probes
  end;
  !flags

let rtf_flags bytes =
  if D_util.starts_with bytes "{\\rtf" then
    List.filter_map (fun (probe, flag) ->
      if D_util.contains_ci bytes probe then Some flag else None)
      [ "{\\objdata", "rtf_objdata";
        "{\\object", "rtf_object" ]
  else []

let filename_flags name =
  let flags = ref [] in
  let add f = if not (List.mem f !flags) then flags := f :: !flags in
  (* bidi overrides in filename *)
  let rec scan i =
    if i >= String.length name then ()
    else begin
      let cp, nxt = D_util.utf8_cp name i in
      if (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)
         || cp = 0x200E || cp = 0x200F then add "rtl_override";
      scan nxt
    end
  in
  scan 0;
  let lower = String.lowercase_ascii name in
  let exts = List.rev (exts_of lower) in
  (match exts with
   | last :: prevs ->
     if List.mem last exec_click_exts then add "exec_ext";
     if List.mem last disk_exts then add "disk_image";
     if List.mem last macro_exts then add "macro_office";
     if prevs <> [] && List.mem last exec_click_exts then add "double_ext";
     if List.exists (fun e -> List.mem e doc_exts) prevs &&
        List.mem last exec_click_exts then add "masquerade_doc"
   | [] -> ());
  if String.length name > 1 &&
     (name.[String.length name - 1] = '.' || name.[String.length name - 1] = ' ') then
    add "trailing_junk";
  !flags

let eicar_prefix = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"

let analyze root =
  let atts = D_mime.attachments root in
  List.map (fun p ->
    let name = match D_mime.filename_of p with Some f -> f | None -> "(unnamed)" in
    let body = p.D_mime.p_body_decoded in
    let size = String.length body in
    let flags = ref (filename_flags name) in
    let add f = if not (List.mem f !flags) then flags := f :: !flags in
    let ctype = p.D_mime.p_type ^ "/" ^ p.D_mime.p_subtype in
    let entries =
      if is_zip body then begin
        let es = zip_entries body in
        if es <> [] then add "archive";
        List.iter (fun e ->
          let le = String.lowercase_ascii e in
          if List.exists (fun m -> D_util.contains_ci le m) macro_markers then add "macro_office";
          if List.exists (fun m -> D_util.ends_with le m) pyc_exts then add "pyc_payload";
          let lexts = exts_of le in
          if List.exists (fun e2 -> List.mem e2 risky_exts) lexts then add "archive_exec";
          if List.mem le [".zip"; ".rar"; ".7z"] || D_util.ends_with le ".zip" ||
             D_util.ends_with le ".rar" || D_util.ends_with le ".7z" then add "nested_archive"
        ) es;
        es
      end else []
    in
    let lname = String.lowercase_ascii name in
    if D_util.ends_with lname ".doc" || D_util.ends_with lname ".xls" ||
       D_util.ends_with lname ".ppt" then add "legacy_office";
    List.iter add (pdf_flags body);
    List.iter add (rtf_flags body);
    (* html attachment *)
    let is_html_att =
      D_util.ends_with lname ".html" || D_util.ends_with lname ".htm" ||
      (ctype = "text/html" &&
       (match p.D_mime.p_disposition with Some d -> d = "attachment" | None -> false)) in
    if is_html_att then begin
      add "html_attachment";
      let urls = D_url.enrich_data_uris (D_url.scan_html body) in
      List.iter (fun u ->
        List.iter (fun f -> add ("att_" ^ f)) u.D_url.u_flags) urls;
      let lower = String.lowercase_ascii body in
      if D_util.contains_ci lower "<script" then add "att_script";
      if D_util.contains_ci lower "http-equiv=\"refresh\"" || D_util.contains_ci lower "http-equiv='refresh'" ||
         D_util.contains_ci lower "http-equiv=refresh" then add "meta_refresh"
    end;
    if D_util.contains_ci body eicar_prefix then add "eicar_test";
    { at_name = D_util.strip_invisible name; at_type = ctype; at_size = size;
      at_flags = List.rev !flags; at_entries = (if List.length entries > 12 then
        let rec take n l = if n = 0 then [] else match l with x :: r -> x :: take (n - 1) r | [] -> [] in
        take 12 entries else entries) }
  ) atts
