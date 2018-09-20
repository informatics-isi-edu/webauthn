from globus_sdk import ConfidentialAppAuthClient
import json
import sys
import pprint

CLIENT_CRED_FILE='/home/secrets/oauth2/client_secret_globus.json'

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {me} access_token".format(me=sys.argv[0]))
        sys.exit(1)
    token = sys.argv[1]
    f=open(CLIENT_CRED_FILE, 'r')
    config=json.load(f)
    f.close()
    client_id = config['web'].get('client_id')
    client_secret = config['web'].get('client_secret')    

    client = ConfidentialAppAuthClient(client_id, client_secret)
    print("Using client id '{client_id}'\n".format(client_id=client_id))
    if client.oauth2_validate_token(token).data.get('active') != True:
        print "not an active token"
        sys.exit(1)
    introspect_response = client.oauth2_token_introspect(token)
    print "token scope is '{scope}'\n".format(scope=introspect_response.get('scope'))
    print "dependent token response is:"
    pprint.pprint(client.oauth2_get_dependent_tokens(token).data)
