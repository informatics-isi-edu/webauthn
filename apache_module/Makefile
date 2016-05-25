install: mod_webauthn.c
	apxs -i -a -c `curl-config --cflags` mod_webauthn.c `curl-config --libs` -ljson

clean:
	rm -f *.la *.lo *.o *.slo
