#!/bin/bash

error()
{
    cat >&2 <<EOF
$0: error: $@
EOF
    exit 1
}

if [[ -d /etc/httpd/conf.d ]]
then
    HTTPSVC=httpd
elif [[ -d /etc/apache2/conf.d ]]
then
    HTTPSVC=apache2
else
    error could not locate Apache HTTPD service config
fi

HTTPCONFDIR=/etc/${HTTPSVC}/conf.d
HTTPSTATICDIR=/var/www/html

for d in ${HTTPSTATICDIR}/test{1..4}
do
    mkdir -p $d || error could not create $d test directory
    cat > $d/test1.txt <<EOF
1
EOF
    [[ $? -eq 0 ]] || error could not create $d/test1.txt test file
    echo created $d/test1.txt
done

c=${HTTPCONFDIR}/webauthn_test.conf
cat > $c <<EOF
WebauthnLoginPath /authn/preauth
WebauthnSessionPath /authn/session
WebauthnVerifySslHost off

<Directory "/var/www/html/test1">
  AuthType webauthn
  Require valid-user
</Directory>

<Directory "/var/www/html/test2">
  AuthType webauthn
  Require webauthn-group admin
</Directory>

<Directory "/var/www/html/test3">
  AuthType webauthn
  Require webauthn-group notagroup
</Directory>

# This should effectively happen by default
#
#<Directory "/var/www/html/test4">
#  Require all granted
#</Directory>

EOF
[[ $? -eq 0 ]] || error could not install $c
echo created $c

exit 0
