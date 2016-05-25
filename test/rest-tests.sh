#!/bin/bash

# Run basic Webauthn REST API tests

usage()
{
    cat <<EOF
usage: $0 <adminuser> <adminpass>  [<nonadminuser> <nonadminpass>]

Runs test against local host (https://$(hostname)/authn/).

A successful run will exit with status 0 and an empty standard output.

A failure will exit with status 1 and a non-empty standard output.

Setting VERBOSE=true will include full per-test information on
standard output for successes as well as failures. VERBOSE=brief will
output a single line per successful test.

Diagnostics may be printed to standard error regardless of success or
failure.

EOF
}

error()
{
    cat <<EOF
$0: $*
EOF
    usage >&2
    exit 1
}

[[ $# -gt 1 ]] || error admin-level user and password required

RUNKEY=smoketest-$RANDOM
RESPONSE_HEADERS=/tmp/${RUNKEY}-response-headers
RESPONSE_CONTENT=/tmp/${RUNKEY}-response-content
TEST_DATA=/tmp/${RUNKEY}-test-data

cleanup()
{
    rm -f ${RESPONSE_HEADERS} ${RESPONSE_CONTENT} ${TEST_DATA}
    rm -f /tmp/parts-${RUNKEY}*
}

trap cleanup 0

COOKIES=${COOKIES:-~/cookie}

declare -a curl_options
curl_options=(
 -D ${RESPONSE_HEADERS}
 -o ${RESPONSE_CONTENT}
 -s -k
 -w "%{http_code}::%{content_type}::%{size_download}\n"
 -b "$COOKIES" -c "$COOKIES"
)

mycurl()
{
    touch ${RESPONSE_HEADERS}
    touch ${RESPONSE_CONTENT}
    truncate -s 0 ${RESPONSE_HEADERS}
    truncate -s 0 ${RESPONSE_CONTENT}
    curl "${curl_options[@]}" "$@"
}

NUM_FAILURES=0
NUM_TESTS=0

BASE_URL="https://$(hostname)/authn"

logtest()
{
    status=$1
    shift
    cat <<EOF
TEST $(( ${NUM_TESTS} + 1 )) $status:

  Request: mycurl $@ ${BASE_URL}$url
  Expected result: $pattern
  Actual result: $summary
$(case "$*" in 
   *${TEST_DATA}*)
     cat <<EOF2

  Request body:
$(sed -e "s/^\(.*\)/    \1/" "${TEST_DATA}")

  Response headers:
EOF2
     ;;
  *)
     cat <<EOF2

  Response headers:
EOF2
     ;;
esac)
$(cat ${RESPONSE_HEADERS} | sed -e "s/^\(.*\)/    \1/")
  Response body:
$(cat ${RESPONSE_CONTENT} | sed -e "s/^\(.*\)/    \1/")

EOF

}

dotest()
{
    pattern="$1"
    url="$2"
    shift 2

    summary=$(mycurl "$@" "${BASE_URL}$url")

    hash1=
    hash2=

    errorpattern="500::*::*"
    
    if [[ "$summary" = $errorpattern ]]
    then
	logtest FAILED "$@"
	error terminating on internal server error
    fi
    
    if [[ "$summary" != $pattern ]]
    then
	logtest FAILED "$@"
	NUM_FAILURES=$(( ${NUM_FAILURES} + 1 ))
    else
	if [[ "$VERBOSE" = "true" ]]
	then
	    logtest OK "$@"
	elif [[ "$VERBOSE" = "brief" ]]
	then
	    cat >&2 <<EOF
TEST $(( ${NUM_TESTS} + 1 )) OK: mycurl $@ ${BASE_URL}$url --> $summary
EOF
	fi
    fi

    NUM_TESTS=$(( ${NUM_TESTS} + 1 ))
}

# baseline before we are logged in
dotest "200::application/json::*" /preauth
dotest "404::*::*" /session
dotest "404::*::*" /session -X PUT

# negative test with invalid login
dotest "401::*::*" /session -d username="baduser11111" -d password="notapassword"

basic_usertest()
{
    # mess up password
    dotest "401::*::*" /session -d username="$1" -d password="$2"bad
    
    # now test with real login
    dotest "200::application/json::*" /session -d username="$1" -d password="$2"
    dotest "409::*::*" /session -d username="$1" -d password="$2"  # can't login twice...

    # work with existing session
    dotest "200::application/json::*" /session
    dotest "200::application/json::*" /session -X PUT

    # check basic information APIs
    dotest "200::application/json:*" /user
    dotest "200::application/json:*" /attribute
    dotest "200::application/json:*" /user/$1
    
    # now logout
    dotest "200::application/json::*" /session -X DELETE
    dotest "404::*::*" /session
}

while [[ $# -gt 0 ]]
do
    [[ $# -gt 1 ]] || error optional arguments must be pairs of username and password
    basic_usertest "$1" "$2"
    shift 2
done
