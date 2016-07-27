
mod_webauthn.la: mod_webauthn.c
	apxs -c -I`apxs -q INCLUDEDIR` `curl-config --cflags` mod_webauthn.c `curl-config --libs` -ljson-c

install: mod_webauthn.la force
	apxs -i mod_webauthn.la

deploy: force
	apxs -e -a mod_webauthn.la

clean:
	rm -f *.la *.lo *.o *.slo
	rm -rf .libs

force:

