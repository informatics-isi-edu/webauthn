#!/bin/bash

# monkey with ssl.conf for travisci (ubuntu) tests

servername=$(hostname)
conf=/etc/apache2/sites-available/ssl.conf
pattern="^\( *\)\(ServerAdmin .*\)"
replacement="\1\2"
replacement+="\1\n# try to avoid server name mismatch errors for mod_webauthn testing"
replacement+="\1\nServerName $servername:443"

mv $conf $conf.orig
sed -e "s|$pattern|$replacement|" \
    < $conf.orig \
    > $conf
chmod u+rw,og=r $conf

