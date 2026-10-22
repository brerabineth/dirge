(* d_selftest - internal assertion suite *)

let failures = ref 0
let checks = ref 0

let assert_eq name a b =
  incr checks;
  if a <> b then begin
    incr failures;
    Printf.printf "FAIL %s\n  got:  %s\n  want: %s\n" name
      (D_util.clip 200 (String.escaped a)) (D_util.clip 200 (String.escaped b))
  end

let assert_eq_i name a b =
  incr checks;
  if a <> b then begin
    incr failures;
    Printf.printf "FAIL %s\n  got:  %d\n  want: %d\n" name a b
  end

let assert_eq_i32 name (a : int32) (b : int32) =
  incr checks;
  if a <> b then begin
    incr failures;
    Printf.printf "FAIL %s\n  got:  %ld\n  want: %ld\n" name a b
  end

let assert_eq_oi name (a : int option) (b : int option) =
  incr checks;
  if a <> b then begin
    incr failures;
    let pr = function Some x -> string_of_int x | None -> "none" in
    Printf.printf "FAIL %s\n  got:  %s\n  want: %s\n" name (pr a) (pr b)
  end

let assert_eq_sl name (a : string list) (b : string list) =
  incr checks;
  if a <> b then begin
    incr failures;
    Printf.printf "FAIL %s\n  got:  %s\n  want: %s\n" name
      (String.concat ", " a) (String.concat ", " b)
  end

let assert_true name cond =
  incr checks;
  if not cond then begin
    incr failures;
    Printf.printf "FAIL %s\n" name
  end

let run () =
  failures := 0; checks := 0;

  (* ---- util ---- *)
  assert_eq "clip.utf8" (D_util.clip 5 "héllo wörld") "héll…";
  assert_true "clip.short" (D_util.clip 20 "abc" = "abc");
  assert_true "contains.ci" (D_util.contains_ci "Verify Your ACCOUNT" "account");
  assert_eq_i "lev.shallow" (D_util.levenshtein "paypa1.com" "paypal.com") 1;
  assert_true "lev.far" (D_util.levenshtein "example.org" "paypal.com" > 3);
  assert_eq_i32 "crc32.hello" (D_util.crc32 "hello") 0x3610A686l;
  (let dec, bad = D_util.b64_decode "aGVsbG8gd29ybGQ=" in
   assert_eq "b64.roundtrip" dec "hello world";
   assert_eq_i "b64.nobad" bad 0);
  assert_eq "qp.decode" (D_util.qp_decode "caf=C3=A9=\r\nnext") "cafénext";
  assert_eq "mask.sk" (D_util.mask_secrets "key sk-abc123def456xyz end") "key sk-[REDACTED] end";
  assert_eq "mask.ghp" (D_util.mask_secrets "ghp_0123456789abcdef") "ghp_[REDACTED]";
  (match D_util.suspicious_unicode "\u{2063}hidden\u{202E}" with
   | [(_, n1); (_, n2)] -> assert_true "uni.bidi_zero" (n1 >= 1 && n2 >= 1)
   | _ -> assert_true "uni.bidi_zero" false);

  (* ---- rfc2047 ---- *)
  assert_eq "2047.b" (D_rfc2047.decode "=?utf-8?B?Q2Fmw6k=?=") "Café";
  assert_eq "2047.q" (D_rfc2047.decode "=?utf-8?Q?Caf=C3=A9_now?=") "Café now";
  assert_eq "2047.adjacent" (D_rfc2047.decode "=?utf-8?B?Q2Fm?= =?utf-8?B?w6k=?=") "Café";
  assert_eq "2047.plain" (D_rfc2047.decode "no encoded words") "no encoded words";
  assert_eq "2047.latin1" (D_rfc2047.decode "=?iso-8859-1?Q?caf=E9?=") "café";
  D_rfc2047.reset_unknown ();

  (* ---- mime ---- *)
  (let raw = "Content-Type: multipart/mixed; boundary=\"OUT\"\r\n\r\n--OUT\r\nContent-Type: text/plain\r\n\r\nhello\r\n--OUT\r\nContent-Type: multipart/alternative; boundary=IN\r\n\r\n--IN\r\nContent-Type: text/plain\r\n\r\nplain body\r\n--IN\r\nContent-Type: text/html\r\n\r\n<b>html body</b>\r\n--IN--\r\n--OUT\r\nContent-Type: application/octet-stream; name=\"a.bin\"\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n\r\nBINBYTES\r\n--OUT--\r\n"
   in
   let root = D_mime.parse raw in
   assert_true "mime.multipart" root.D_mime.p_is_mp;
   assert_eq_i "mime.childcount" (List.length root.D_mime.p_children) 3;
   let leaves = D_mime.flatten root in
   assert_eq_i "mime.leafcount" (List.length leaves) 4;
   (match D_mime.best_text root with
    | t, _ -> assert_eq "mime.besttext" t "hello\n");
   assert_eq_i "mime.attcount" (List.length (D_mime.attachments root)) 1;
   assert_eq "mime.filename"
     (match D_mime.attachments root with
      | a :: _ -> (match D_mime.filename_of a with Some f -> f | None -> "")
      | [] -> "") "a.bin";
   assert_true "mime.no_warn_closed" (not (List.mem "multipart not closed with final boundary" !D_mime.parse_warnings)));
  (* missing final boundary *)
  (let raw = "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nx\r\n"
   in
   D_mime.reset_warn ();
   let _ = D_mime.parse raw in
   assert_true "mime.open_multipart" (List.mem "multipart not closed with final boundary" !D_mime.parse_warnings);
   D_mime.reset_warn ());
  (* rfc2231 filename *)
  (let raw = "Content-Type: text/plain\r\nContent-Disposition: attachment; filename*=UTF-8''inv%20oice.pdf\r\n\r\nx\r\n"
   in
   let root = D_mime.parse raw in
   assert_eq "mime.rfc2231"
     (match D_mime.attachments root with
      | a :: _ -> (match D_mime.filename_of a with Some f -> f | None -> "")
      | [] -> "") "inv oice.pdf");
  (* message/rfc822 nesting *)
  (let raw = "Content-Type: message/rfc822\r\n\r\nSubject: inner\r\nFrom: x@y.z\r\n\r\ninner body\r\n"
   in
   let root = D_mime.parse raw in
   assert_true "mime.nested" (match root.D_mime.p_nested with Some _ -> true | None -> false));

  (* ---- headers: dates ---- *)
  assert_eq_oi "date.rfc" (D_headers.parse_date "Wed, 7 Oct 2026 09:15:00 +0000")
    (Some (D_headers.days_from_civil 2026 10 7 * 86400 + 9 * 3600 + 15 * 60));
  assert_eq_oi "date.2digit" (D_headers.parse_date "7 Oct 26 09:15:00 +0000")
    (Some (D_headers.days_from_civil 2026 10 7 * 86400 + 9 * 3600 + 15 * 60));
  assert_eq_oi "date.pst" (D_headers.parse_date "Wed, 7 Oct 2026 09:15:00 PST")
    (Some (D_headers.days_from_civil 2026 10 7 * 86400 + 9 * 3600 + 15 * 60 + 8 * 3600));
  assert_true "date.garbage" (D_headers.parse_date "not a date" = None);
  assert_eq_i "days.civil" (D_headers.days_from_civil 1970 1 1) 0;
  assert_eq_i "days.civil2" (D_headers.days_from_civil 2024 3 1) 19783;

  (* ---- headers: addrs ---- *)
  (match D_headers.parse_addrs "\"PayPal Team\" <pay@evil.example>, other@ok.example" with
   | a :: b :: _ ->
     assert_eq "addr.name" a.D_headers.a_name "PayPal Team";
     assert_eq "addr.email" a.D_headers.a_email "pay@evil.example";
     assert_eq "addr.plain" b.D_headers.a_email "other@ok.example"
   | _ -> assert_true "addr.count" false);
  assert_eq "addr.domain" (D_headers.domain_of "a@Mail.Evil.Example") "mail.evil.example";

  (* ---- headers: auth ---- *)
  (let a = D_headers.parse_auth
     ["mx.example.org; spf=fail smtp.mailfrom=x@e.example; dkim=none; dmarc=fail header.from=e.example"] in
   assert_eq "auth.spf" a.D_headers.spf "fail";
   assert_eq "auth.dkim" a.D_headers.dkim "none";
   assert_eq "auth.dmarc" a.D_headers.dmarc "fail";
   let b = D_headers.parse_auth [] in
   assert_true "auth.empty" (not b.D_headers.present));

  (* ---- ips ---- *)
  assert_eq_sl "ips.parse" (D_headers.ips_in "from h (rdns [198.51.100.7]) by m") ["198.51.100.7"];

  (* ---- urls ---- *)
  (let urls = D_url.scan_text "go to https://PayPal-Secure.example.com/login?next=https://bit.ly/x and http://198.51.100.9/a.js now" "body" in
   assert_eq_i "url.count" (List.length urls) 2;
   (match urls with
    | u1 :: _ ->
      assert_true "url.brand" (List.mem "brand_token" u1.D_url.u_flags);
      assert_true "url.cred" (List.mem "credential_path" u1.D_url.u_flags);
      assert_true "url.no_tls_not" (not (List.mem "no_tls" u1.D_url.u_flags))
    | [] -> assert_true "url.first" false));
  (let urls = D_url.scan_text "go http://bit.ly/3aB http://xn--80ak6aa92e.info ftp://files.example.org/x" "body" in
   assert_eq_i "url.count2" (List.length urls) 3;
   let flags = List.concat_map (fun u -> u.D_url.u_flags) urls in
   assert_true "url.short" (List.mem "shortener" flags);
   assert_true "url.puny" (List.mem "punycode" flags);
   assert_true "url.ftp" (List.mem "odd_scheme" flags));
  (* entity-encoded href *)
  (let urls = D_url.analyze_html "<a href=\"http://secure-login.example\u{002F}verify?a=1&#64;x\">c</a>" in
   assert_true "url.entity" (List.exists (fun u -> u.D_url.u_host = "secure-login.example") urls));
  (* data uri credential form *)
  (let payload = D_url.entity_decode "&lt;form action=&quot;http://x&quot;&gt;&lt;input type=&quot;password&quot;&gt;" in
   assert_true "entity.form" (D_util.contains_ci payload "<form"));
  (let html = "<a href=\"data:text/html;base64," ^ D_forge.b64_of D_forge.smuggle_doc ^ "\">v</a>" in
   let urls = D_url.analyze_html html in
   (match List.filter (fun u -> u.D_url.u_kind = "data") urls with
    | u :: _ ->
      assert_true "data.payload" (D_util.contains_ci u.D_url.u_payload "<form");
      assert_true "data.cred" (List.mem "credential_form" u.D_url.u_flags)
    | [] -> assert_true "data.present" false));
  (* tracking pixel *)
  assert_true "pixel.yes" (D_url.is_tracking_pixel "<img src=\"http://m.example/p.png\" width=\"1\" height=\"1\">");
  assert_true "pixel.no" (not (D_url.is_tracking_pixel "<img src=\"http://m.example/big.png\" width=\"600\" height=\"200\">"));
  (* hidden text probes *)
  assert_eq_sl "hidden.probes" (D_url.hidden_text_hits "<div style=\"display:none\">x</div>") ["display:none"];
  (* typosquat *)
  (let urls = D_url.scan_text "visit https://paypa1.com/login now" "body" in
   (match urls with
    | u :: _ -> assert_true "url.typosquat" (List.mem "typosquat" u.D_url.u_flags)
    | [] -> assert_true "url.typosquat.exist" false));

  (* ---- attachments ---- *)
  (* filename risks *)
  assert_true "att.double" (List.mem "double_ext" (D_attach.filename_flags "invoice.pdf.exe"));
  assert_true "att.rtl" (List.mem "rtl_override" (D_attach.filename_flags "inv\u{202E}fdp.exe"));
  assert_true "att.masq" (List.mem "masquerade_doc" (D_attach.filename_flags "report.pdf.exe"));
  assert_true "att.macro_ext" (List.mem "macro_office" (D_attach.filename_flags "update.docm"));
  assert_true "att.iso" (List.mem "disk_image" (D_attach.filename_flags "setup.iso"));
  assert_true "att.plain_ok" (D_attach.filename_flags "photo.jpg" = []);
  (* zip walk on generated docx *)
  assert_true "att.zipwalk" (List.exists (fun e -> D_util.contains_ci e "vbaProject") (D_attach.zip_entries D_forge.fake_docx));
  (let raw = "Content-Type: multipart/mixed; boundary=Z\r\n\r\n--Z\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name=\"Security_Update.docx\"\r\nContent-Disposition: attachment; filename=\"Security_Update.docx\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" ^ D_forge.wrap76 (D_forge.b64_of D_forge.fake_docx) ^ "\r\n--Z--\r\n"
   in
   D_mime.reset_warn ();
   let root = D_mime.parse raw in
   let atts = D_attach.analyze root in
   (match atts with
    | a :: _ ->
      assert_true "att.macro_zip" (List.mem "macro_office" a.D_attach.at_flags);
      assert_true "att.archive" (List.mem "archive" a.D_attach.at_flags)
    | [] -> assert_true "att.present" false));
  (* pdf flags *)
  assert_true "att.pdf" (List.mem "pdf_launch" (D_attach.pdf_flags "%PDF-1.7 /Launch (cmd)"));
  assert_true "att.notpdf" (D_attach.pdf_flags "not a pdf" = []);
  (* rtf *)
  assert_true "att.rtf" (List.mem "rtf_objdata" (D_attach.rtf_flags "{\\rtf1{\\objdata 00}"));

  (* ---- ai template ---- *)
  (let html = "<!-- Main Content --><div style=\"border-left:4px solid #333\">x</div><a style=\"background:#333; border-radius:8px\">1</a><a style=\"background:#444; border-radius:8px\">2</a>" in
   let lik, markers = D_aitmpl.assess html in
   assert_eq "aitmpl.likely" lik "likely";
   assert_true "aitmpl.markers" (List.length markers >= 3));
  (let lik, _ = D_aitmpl.assess "<p>plain human email</p>" in
   assert_eq "aitmpl.none" lik "none");

  (* ---- rules ---- *)
  (let f0 = [] in
   assert_true "rules.clean" (match D_rules.verdict_of_findings f0 with D_rules.VClean, _, _ -> true | _ -> false));
  (let fs = D_rules.assemble [("h.auth_missing", ["x"])] in
   assert_true "rules.watch" (match D_rules.verdict_of_findings fs with D_rules.VWatch, _, _ -> true | _ -> false);
   assert_eq_i "rules.weight" (D_rules.weight_of "h.auth_missing") 12);
  (let fs = D_rules.assemble [("h.dmarc_fail", ["x"]); ("h.spf_fail", ["y"])] in
   assert_true "rules.suspicious" (match D_rules.verdict_of_findings fs with D_rules.VSuspicious, _, _ -> true | _ -> false));
  (let fs = D_rules.assemble [("a.rtl_override", ["x"])] in
   assert_true "rules.force_hostile" (match D_rules.verdict_of_findings fs with D_rules.VHostile, _, true -> true | _ -> false));
  (let fs = D_rules.assemble [("a.macro_office", ["x"]); ("u.brand_token", ["y"])] in
   assert_true "rules.combo_force" (match D_rules.verdict_of_findings fs with D_rules.VHostile, _, true -> true | _ -> false));
  assert_eq_i "rules.exit" (D_rules.exit_of_verdict D_rules.VSuspicious) 3;
  assert_eq_i "rules.catalog_unique"
    (List.length (List.map (fun (i, _) -> i) D_rules.catalog))
    (List.length (List.sort_uniq compare (List.map (fun (i, _) -> i) D_rules.catalog)));

  (* ---- end-to-end on fixtures ---- *)
  (let dir = Filename.concat (Filename.get_temp_dir_name ()) "dirge_selftest_fixtures" in
   if Sys.file_exists dir then () else Unix.mkdir dir 0o755;
   D_forge.forge dir;
   let scan n = D_scan.scan_raw (Filename.concat dir n) (D_util.read_file (Filename.concat dir n)) in
   (* forge determinism: re-forge elsewhere and compare bytes *)
   let dir2 = Filename.concat (Filename.get_temp_dir_name ()) "dirge_selftest_fixtures2" in
   if Sys.file_exists dir2 then () else Unix.mkdir dir2 0o755;
   D_forge.forge dir2;
   List.iter (fun (name, _) ->
     assert_eq ("forge.det " ^ name)
       (D_util.read_file (Filename.concat dir name))
       (D_util.read_file (Filename.concat dir2 name))) D_forge.scenario_names;
   (* verdict census *)
   assert_eq "e2e.newsletter" (D_rules.verdict_name (scan "01_newsletter.eml").D_scan.sr_verdict) "clean";
   assert_eq "e2e.spoofed" (D_rules.verdict_name (scan "02_spoofed_bank.eml").D_scan.sr_verdict) "hostile";
   assert_eq "e2e.smuggle" (D_rules.verdict_name (scan "03_smuggle.eml").D_scan.sr_verdict) "hostile";
   assert_eq "e2e.aitmpl" (D_rules.verdict_name (scan "04_ai_template.eml").D_scan.sr_verdict) "watch";
   assert_eq "e2e.macro" (D_rules.verdict_name (scan "05_macro_docx.eml").D_scan.sr_verdict) "hostile";
   assert_eq "e2e.inflation" (D_rules.verdict_name (scan "06_inflation.eml").D_scan.sr_verdict) "hostile";
   (* specific rule presence *)
   assert_true "e2e.spoofed.dmarc"
     (List.exists (fun f -> f.D_rules.f_id = "h.dmarc_fail") (scan "02_spoofed_bank.eml").D_scan.sr_findings);
   assert_true "e2e.spoofed.replyto"
     (List.exists (fun f -> f.D_rules.f_id = "h.replyto_mismatch") (scan "02_spoofed_bank.eml").D_scan.sr_findings);
   assert_true "e2e.spoofed.masq"
     (List.exists (fun f -> f.D_rules.f_id = "a.masquerade_doc") (scan "02_spoofed_bank.eml").D_scan.sr_findings);
   assert_true "e2e.spoofed.redirector"
     (List.exists (fun f -> f.D_rules.f_id = "u.redirector_param") (scan "02_spoofed_bank.eml").D_scan.sr_findings);
   assert_true "e2e.smuggle.cred"
     (List.exists (fun f -> f.D_rules.f_id = "u.credential_form") (scan "03_smuggle.eml").D_scan.sr_findings);
   assert_true "e2e.smuggle.pixel"
     (List.exists (fun f -> f.D_rules.f_id = "u.tracking_pixel") (scan "03_smuggle.eml").D_scan.sr_findings);
   assert_true "e2e.aitmpl.template"
     (List.exists (fun f -> f.D_rules.f_id = "t.ai_template") (scan "04_ai_template.eml").D_scan.sr_findings);
   assert_true "e2e.macro.combo"
     (List.exists (fun f -> f.D_rules.f_id = "a.macro_office") (scan "05_macro_docx.eml").D_scan.sr_findings);
   assert_true "e2e.inflation.pad"
     (List.exists (fun f -> f.D_rules.f_id = "b.inflation") (scan "06_inflation.eml").D_scan.sr_findings);
   assert_true "e2e.inflation.ctx"
     (List.exists (fun f -> f.D_rules.f_id = "b.ctx_manipulation") (scan "06_inflation.eml").D_scan.sr_findings);
   (* determinism of scan output *)
   assert_eq "e2e.json.deterministic"
     (D_report.json [scan "02_spoofed_bank.eml"])
     (D_report.json [scan "02_spoofed_bank.eml"]);
   (* json shape: single line, sorted keys *)
   let j = D_report.json [scan "01_newsletter.eml"] in
   assert_true "json.singleline" (not (String.contains j '\n'));
   assert_true "json.canonical" (D_util.starts_with j "{\"results\":[" && D_util.ends_with j "}");
   (* masking in evidence *)
   let masked = D_report.json [scan "02_spoofed_bank.eml"] in
   assert_true "json.masked_urls" (not (D_util.contains_ci masked "http://"));
   (* md render works *)
   assert_true "md.renders" (String.length (D_report.md [scan "01_newsletter.eml"]) > 100);
   (* terminal render works *)
   assert_true "term.renders" (String.length (D_report.terminal [scan "02_spoofed_bank.eml"]) > 200));

  (* summary *)
  Printf.printf "selftest: %d checks, %d failures\n" !checks !failures;
  !failures
