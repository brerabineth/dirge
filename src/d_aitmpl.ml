(* d_aitmpl - AI-assisted template heuristics (Hoxhunt 2026 methodology) *)

type marker = {
  m_kind : string;      (* generic_comment | emoji_cta | rounded_button | highlight_box *)
  m_evidence : string;
}

let generic_labels = [
  "main content"; "content section"; "section 1"; "section 2"; "section 3";
  "click to call"; "call to action"; "hero section"; "header section";
  "footer section"; "main section"; "button text"; "cta button";
  "intro text"; "body text"; "step 1"; "step 2"; "step 3";
  "insert text here"; "your text here"; "placeholder"
]

let emoji_ranges cp =
  (cp >= 0x1F300 && cp <= 0x1FAFF)
  || (cp >= 0x2600 && cp <= 0x27BF)
  || (cp >= 0x2190 && cp <= 0x21FF && cp <> 0x21D2)
  || cp = 0xFE0F

(* html comments that look machine-labeled *)
let generic_comments html =
  let res = ref [] in
  let n = String.length html in
  let i = ref 0 in
  while !i + 4 <= n do
    if html.[!i] = '<' && html.[!i + 1] = '!' && html.[!i + 2] = '-' && html.[!i + 3] = '-' then begin
      match (try String.index_from html (!i + 4) '>' with Not_found -> -1) with
      | gt when gt > 0 ->
        let raw = String.sub html (!i + 4) (gt - !i - 4) in
        let raw = (if String.length raw >= 2 && D_util.ends_with raw "--" then
                     String.sub raw 0 (String.length raw - 2) else raw) in
        let low = String.lowercase_ascii (D_util.trim raw) in
        if List.exists (fun lbl -> D_util.contains_ci low lbl) generic_labels then
          res := D_util.trim raw :: !res;
        i := gt + 1
      | _ -> incr i
    end else incr i
  done;
  List.rev !res

(* emoji inside anchor text *)
let emoji_ctas html =
  let n = String.length html in
  let lower = String.lowercase_ascii html in
  let res = ref [] in
  let i = ref 0 in
  while !i + 3 <= n do
    if D_util.starts_with (String.sub lower !i (min 3 (n - !i))) "<a " ||
       D_util.starts_with (String.sub lower !i (min 9 (n - !i))) "<a href" then begin
      let close = try String.index_from lower (!i + 1) '>' with Not_found -> n - 1 in
      let close_tag = (try String.index_from lower (close + 1) '<' with Not_found -> n - 1) in
      if close_tag > close && close_tag + 4 <= n then begin
        let text = String.sub html (close + 1) (close_tag - close - 1) in
        let emoji_count = ref 0 in
        let j = ref 0 in
        while !j < String.length text do
          let cp, nxt = D_util.utf8_cp text !j in
          if emoji_ranges cp then incr emoji_count;
          j := nxt
        done;
        if !emoji_count > 0 then
          res := Printf.sprintf "%d emoji in link text: %s" !emoji_count
                   (D_util.clip 40 (D_util.strip_invisible (D_url.html_text text))) :: !res;
        i := close_tag + 4
      end else i := close + 1
    end else incr i
  done;
  List.rev !res

(* rounded-corner buttons: border-radius on anchor/td with background *)
let rounded_buttons html =
  let n = String.length html in
  let lower = String.lowercase_ascii html in
  let count = ref 0 in
  let i = ref 0 in
  while !i + 3 <= n do
    if (D_util.starts_with (String.sub lower !i (min 3 (n - !i))) "<a ") ||
       (D_util.starts_with (String.sub lower !i (min 4 (n - !i))) "<td ") ||
       (D_util.starts_with (String.sub lower !i (min 5 (n - !i))) "<div ") then begin
      let stop = try String.index_from lower !i '>' with Not_found -> n - 1 in
      let tag = String.sub lower !i (stop - !i + 1) in
      if D_util.contains_ci tag "border-radius" &&
         (D_util.contains_ci tag "background" || D_util.contains_ci tag "bgcolor") then
        incr count;
      i := stop + 1
    end else incr i
  done;
  !count

(* highlight box: thick left border *)
let highlight_boxes html =
  let lower = String.lowercase_ascii html in
  let hits = ref [] in
  let probes = ["border-left:"; "border-left :"] in
  List.iter (fun p ->
    let n = String.length lower in
    let pos = ref 0 in
    let rec go () =
      if !pos < n then
        match D_util.find_ci (String.sub lower !pos (n - !pos)) p with
        | Some k ->
          let k = !pos + k in
          let seg = String.sub lower k (min 60 (n - k)) in
          let tail = String.sub seg (min (String.length p) (String.length seg))
                     (max 0 (min 6 (String.length seg - (min (String.length p) (String.length seg))))) in
          let digits = ref 0 in
          String.iter (fun c -> if c >= '1' && c <= '9' then incr digits) tail;
          if !digits > 0 && D_util.contains_ci seg "solid" then
            hits := D_util.clip 48 (String.sub lower k (min 48 (n - k))) :: !hits;
          pos := k + 1;
          go ()
        | None -> ()
    in
    go ()) probes;
  !hits

let assess html =
  let comments = generic_comments html in
  let emojis = emoji_ctas html in
  let rounded = rounded_buttons html in
  let boxes = highlight_boxes html in
  let markers = ref [] in
  List.iter (fun c -> markers := { m_kind = "generic_comment"; m_evidence = "<!-- " ^ c ^ " -->" } :: !markers) comments;
  List.iter (fun e -> markers := { m_kind = "emoji_cta"; m_evidence = e } :: !markers) emojis;
  if rounded >= 2 then
    markers := { m_kind = "rounded_button"; m_evidence = Printf.sprintf "%d rounded buttons" rounded } :: !markers;
  List.iter (fun b -> markers := { m_kind = "highlight_box"; m_evidence = b } :: !markers) boxes;
  let distinct_kinds =
    List.map (fun m -> m.m_kind) !markers |> List.sort_uniq compare |> List.length in
  let likelihood =
    if distinct_kinds >= 3 then "likely"
    else if distinct_kinds = 2 then "elevated"
    else if distinct_kinds = 1 then "possible"
    else "none"
  in
  (likelihood, List.rev !markers)
