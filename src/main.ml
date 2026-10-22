(* main - cli entry *)

let usage = "usage: dirge scan [-o out] [--json|--md] [--min-score N] <file|dir|- ...>\n" ^
            "       dirge forge <outdir>       write deterministic demo fixtures\n" ^
            "       dirge rules                print the finding catalog\n" ^
            "       dirge explain              methodology and scoring notes\n" ^
            "       dirge selftest             run the internal assertion suite\n" ^
            "       dirge version              print version"

let print_rules () =
  print_endline D_util.banner;
  print_newline ();
  print_endline "  finding catalog (weight, severity, id, title)";
  print_endline D_util.sep;
  List.iter (fun (id, (w, sev, title)) ->
    Printf.printf "  %6d  %-8s  %-22s  %s\n"
      w (D_rules.sev_name sev) id title) D_rules.catalog;
  print_newline ();
  print_endline "  bands: clean <10  watch <25  suspicious <60  hostile >=60";
  print_endline ("  forced hostile: " ^ String.concat ", " D_rules.force_hostile);
  print_endline "  combo force: macro_office + (brand_token | display_spoof)";
  print_endline "               inflation + ctx_manipulation";
  print_endline "  exit codes: clean=0 watch=1 suspicious=3 hostile=10 usage=2"

let print_explain () =
  print_endline D_util.banner;
  print_newline ();
  print_endline "  why an email autopsy, offline";
  print_endline D_util.sep;
  print_endline "  - AI-assisted phish went from 4% of reported samples (nov 2025) to";
  print_endline "    56% (dec 2025) and stayed high through 2026 (Hoxhunt trend report).";
  print_endline "    AI lures reach 54% click-through vs 12% for human-written ones.";
  print_endline "  - most tooling for mail triage is either a SaaS gateway or a";
  print_endline "    scattered python script. a single native binary that never touches";
  print_endline "    the network and answers with an exit code fills the gap for";
  print_endline "    pipelines, air-gapped review and quick one-off checks.";
  print_newline ();
  print_endline "  what it reads";
  print_endline D_util.sep;
  print_endline "  - rfc5322 headers, rfc2047 encoded words, mime trees (multipart,";
  print_endline "    message/rfc822 nesting, rfc2231 extended params), base64 and";
  print_endline "    quoted-printable bodies. archives are walked by central directory";
  print_endline "    (docx/xlsx/pptx included) so vba projects and .pyc payloads are";
  print_endline "    named even without unzipping.";
  print_newline ();
  print_endline "  what it checks";
  print_endline D_util.sep;
  print_endline "  - auth chain (spf/dkim/dmarc results), reply-to / return-path /";
  print_endline "    message-id domain mismatches, brand display-name spoofing";
  print_endline "  - urls: brand tokens outside real domains, typosquat distance,"; 
  print_endline "    punycode, raw ips, shorteners, open-redirect params, credential";
  print_endline "    paths, embedded data: html documents (decoded and re-scanned)";
  print_endline "  - attachments: extension masquerade, bidi-override filename spoofs,";
  print_endline "    office macros, pdf actions, rtf objects, html smuggling";
  print_endline "  - content: agent-directed instructions (mail read by machines),";
  print_endline "    urgency/credential/scare/crypto/callback phrasing, invisible";
  print_endline "    unicode, whitespace inflation (the scanner-truncation trick),";
  print_endline "    hidden bait text, tracking pixels";
  print_endline "  - AI-assisted template fingerprints per the 2026 phishing trends";
  print_endline "    methodology: generic html comments, emoji ctas, rounded buttons,";
  print_endline "    highlight boxes";
  print_newline ();
  print_endline "  scoring";
  print_endline D_util.sep;
  print_endline "  findings carry weights, the sum maps to a band and an exit code.";
  print_endline "  certain findings force hostile regardless of the sum (bidi filename";
  print_endline "  spoofs, credential forms in embedded documents, masquerade docs,";
  print_endline "  invisible text) plus two combos (macros+brand, padding+agent bait).";
  print_endline "  'dirge rules' prints the full catalog with weights."

let main () =
  let args = Sys.argv in
  let n = Array.length args in
  if n < 2 then begin
    prerr_endline usage;
    exit 2
  end;
  (match args.(1) with
   | "version" | "--version" | "-v" ->
     Printf.printf "dirge %s\n" D_util.version
   | "rules" -> print_rules ()
   | "explain" -> print_explain ()
   | "selftest" ->
     let code = D_selftest.run () in
     exit code
   | "forge" ->
     if n < 3 then begin prerr_endline "usage: dirge forge <outdir>"; exit 2 end;
     D_forge.forge args.(2);
     Printf.printf "fixtures written to %s\n" args.(2)
   | "scan" ->
     let targets = ref [] in
     let json_f = ref false and md_f = ref false and min_score = ref 0 in
     let out_path = ref None in
     let i = ref 2 in
     (try
        while !i < n do
          (match args.(!i) with
           | "--json" -> json_f := true
           | "--md" -> md_f := true
           | "--min-score" -> min_score := int_of_string args.(!i + 1); i := !i + 1
           | "-o" -> out_path := Some args.(!i + 1); i := !i + 1
           | "--color" -> D_util.color_flag := true
           | "--no-color" -> D_util.color_flag := false
           | "-" -> targets := "-" :: !targets
           | t -> targets := t :: !targets);
          incr i
        done
      with _ -> (prerr_endline usage; exit 2));
     if !targets = [] then begin prerr_endline usage; exit 2 end;
     let targets = List.rev !targets in
     let files =
       if targets = ["-"] then []
       else D_util.collect_eml (List.filter (fun t -> t <> "-") targets)
     in
     let use_stdin = List.exists (fun t -> t = "-") targets in
     if files = [] && not use_stdin then begin
       prerr_endline "dirge: no .eml files found";
       exit 2
     end;
     let results =
       List.map (fun f -> try D_scan.scan_raw f (D_util.read_file f) with
         | Sys_error m -> begin
             prerr_endline ("dirge: " ^ m);
             exit 2 end) files
       @ (if use_stdin then [D_scan.scan_raw "<stdin>" (D_util.read_stdin_all ())] else [])
     in
     (* --min-score filters rendered detail (score threshold on output) *)
     let shown = List.filter (fun r -> r.D_scan.sr_score >= !min_score) results in
     let rendered =
       if !json_f then D_report.json results
       else if !md_f then D_report.md results
       else D_report.terminal shown
     in
     (match !out_path with
      | Some p -> let oc = open_out_bin p in output_string oc rendered; close_out oc
      | None -> print_string rendered);
     let overall = List.fold_left (fun acc r ->
       if D_rules.exit_of_verdict r.D_scan.sr_verdict > D_rules.exit_of_verdict acc
       then r.D_scan.sr_verdict else acc) D_rules.VClean results in
     exit (D_rules.exit_of_verdict overall)
   | _ ->
     prerr_endline usage;
     exit 2)

let () = main ()
