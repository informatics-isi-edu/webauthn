import json
import argparse
from os.path import expanduser
import sys
import subprocess

SHAREDIR="/usr/share/webauthn2/v2_upgrade"

ermrest_webauthn_schema=None
hatrac_webauthn_schema=None

parser=argparse.ArgumentParser()
parser.add_argument('-e', '--ermrest-only', help="look only at ermrest config", action='store_true')
parser.add_argument('-H', '--hatrac-only', help="look only at hatrac config", action='store_true')
ns=parser.parse_args()

def find_webauthn_schema(filename):
    val=None
    try:
        f=open(filename, "r")
    except IOError, ex:
        if ex.errno == 2:
            print("No {f} file, skipping...".format(f=ex.filename))
            return None
        else:
            raise RuntimeError("Can't read {f}: {e}. Giving up.".format(f=ex.filename, e=ex.strerror))
    try:
        val=json.load(f)
    except Exception:
        raise RuntimeError("Error decoding json in {f}. Giving up.".format(f=filename))
    f.close()
    webauthn_config = val.get('webauthn2')
    if webauthn_config == None:
        webauthn_config=val
    if webauthn_config == None or webauthn_config.get('sessionstates_provider') == None:
        raise RuntimeError("Can't find webauthn config in {f}".format(f=filename))
    return webauthn_config.get('database_schema')


def process(user, filename):
    file="{dir}/{file}".format(dir=expanduser("~{user}".format(user=user)),file=filename)
    schema=find_webauthn_schema(file)
    if schema == None:
        print("no webauthn schema found in {f}. Skipping...".format(f=file))
    else:
        print("upgrading {user} schema {schema}...".format(user=user, schema=schema))
        subprocess.call(["su", "-c", "psql -f {sharedir}/webauthn2_v2_upgrade.sql --variable=myschema={schema}".format(schema=schema, sharedir=SHAREDIR), user])

if not ns.hatrac_only:
    process('ermrest', 'ermrest_config.json')
    
if not ns.ermrest_only:
    process('hatrac', 'webauthn2_config.json')




