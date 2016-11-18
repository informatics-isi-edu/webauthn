#!/bin/bash

# Run basic mod_webauthn static file tests

usage()
{
    cat <<EOF
usage: $0 <adminuser> <adminpass>

Runs test against local host (https://$(hostname)/) assuming a
default deployment of the REST API to /authn and the necessary
test files under /test1 .. /test4 via test/static-test-setup.sh.

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

HTTPD_ERROR_LOG=${HTTPD_ERROR_LOG:-/var/log/httpd/ssl_error_log}

cleanup()
{
    rm -f ${RESPONSE_HEADERS} ${RESPONSE_CONTENT} ${TEST_DATA}
    rm -f /tmp/parts-${RUNKEY}*
}

trap cleanup 0

COOKIES=${COOKIES:-~/staticcookie}

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

BASE_URL="https://$(hostname)"

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

	if [[ -r "${HTTPD_ERROR_LOG}" ]]
	then
	    cat >&2 <<EOF

Excerpt from ${HTTPD_ERROR_LOG}:

EOF
	    tail -100 "${HTTPD_ERROR_LOG}" | sed -e 's/^/    /' >&2
	fi
	
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

get_expiration()
{
    dotest "200::application/json::*" /authn/session
    date -d "$(sed -e 's|.*"expires": *"\([^"]*\)".*|\1|' < ${RESPONSE_CONTENT})" +%s
}

# baseline before we are logged in
dotest "200::application/json::*" /authn/preauth
dotest "404::*::*" /authn/session
dotest "404::*::*" /authn/session -X PUT

dotest "401::*::*" /test1/test1.txt
dotest "401::*::*" /test2/test1.txt
dotest "401::*::*" /test3/test1.txt
dotest "200::*::2" /test4/test1.txt

# now test with real login
dotest "200::application/json::*" /authn/session -d username="$1" -d password="$2"
expires0=$(get_expiration)
now=$(date +%s)

for s in {1..10}
do
    dotest "200::*::2" /test1/test1.txt
    expires1=$(get_expiration)

    if [[ $expires1 -gt $expires0 ]]
    then
	break
    fi
    
    if [[ "$VERBOSE" = true ]] || [[ "$VERBOSE" = brief ]]
    then
	echo sleeping 5 seconds... >&2
    fi
    sleep 5
done

dotest "200::*::2" /test2/test1.txt
dotest "403::*::*" /test3/test1.txt
dotest "200::*::2" /test4/test1.txt
expires1=$(get_expiration)

if [[ ${expires1} -gt ${expires0} ]]
then
    if [[ "$VERBOSE" = true ]] || [[ "$VERBOSE" = brief ]]
    then
	cat >&2 <<EOF
TEST $(( ${NUM_TESTS} + 1 )) OK: static file access postponed session expiration $(( $expires1 - $expires0 )) seconds.
EOF
    fi
else
    if [[ "$VERBOSE" = true ]] || [[ "$VERBOSE" = brief ]]
    then
	cat >&2 <<EOF
TEST $(( ${NUM_TESTS} + 1 )) FAILED: static file access failed to postpone session expiration.
EOF
    fi
fi
NUM_TESTS=$(( ${NUM_TESTS} + 1 ))



# now logout
dotest "200::application/json::*" /authn/session -X DELETE

if [[ ${NUM_FAILURES} -gt 0 ]]
then
    echo "FAILED ${NUM_FAILURES} of ${NUM_TESTS} tests" 
    exit 1
else
    echo "ALL ${NUM_TESTS} tests succeeded" >&2
    exit 0
fi
