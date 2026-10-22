OCAML := ocamlopt.opt
ifeq ($(shell command -v ocamlopt.opt 2>/dev/null),)
OCAML := ocamlopt
endif

MODULES := d_util d_rfc2047 d_mime d_headers d_url d_attach d_aitmpl \
           d_rules d_forge d_scan d_report d_selftest main

.PHONY: all test fixtures clean

all:
	for m in $(MODULES); do $(OCAML) -c -I src src/$$m.ml || exit 1; done
	$(OCAML) -I +str str.cmxa -I +unix unix.cmxa -I src \
	  $(addprefix src/,$(addsuffix .cmx,$(MODULES))) -o dirge

test: all
	./dirge selftest

fixtures: all
	./dirge forge fixtures

clean:
	rm -f dirge src/*.cmi src/*.cmx src/*.o
