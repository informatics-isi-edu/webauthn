#!/bin/bash

# check credential file from webauthn2-manage addrobot...

# usage: $0 credfilename
#
# this test requires the caller to have already performed setup such
# as:  webauthn2-manage addrobot dummyrobot credfilename 5

require()
{
    test_name="$1"
    shift

    "$@" >&2
    status=$?
    printf "${test_name}: "
    if [[ $status -ne 0 ]]
    then
	echo "FAILED"
	cat >&2 <<EOF
   "$@" returned status $status
EOF
	exit 1
    else
	echo "OK"
	return 0
    fi
}

require "readable credential" [ -r "$1" ]

require "cookie in credential" grep -q '"cookie":' "$1"

cookie_hdr=$(grep '"cookie":' "$1" | sed -e 's/ *"cookie": *"\([^"]*\)".*/\1/')

require "non-empty cookie header" [ -n "${cookie_hdr}" ]

require "found session" curl -f -H "Cookie: ${cookie_hdr}" "https://$(hostname)/authn/session"
