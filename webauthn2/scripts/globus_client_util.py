from globus_sdk import ConfidentialAppAuthClient
import json
import sys

CLIENT_CRED_FILE='/home/secrets/oauth2/client_secret_globus.json'

class GlobusClientUtil:
    def __init__(self, *args, **kwargs):
        # GlobusClientUtil(<filename>) reads client id and secret from <filename>
        # GlobusClientUtil() is equivalent to GlobusClientUtil('/home/secrets/oauth2/client_secret_globus.json')
        # GlobusClientUtil(client_id, client_secret) uses the specified id and secret instead of reading from a file.
        cred_file = CLIENT_CRED_FILE
        if len(args) == 1:
            cred_file=args[0]
        if len(args) < 2:
            f=open(cred_file, 'r')
            config=json.load(f)
            f.close()
            self.initialize(config['web'].get('client_id'), config['web'].get('client_secret'))
        elif len(args) == 2:
            self.initialize(args[0], args[1])

    def initialize(self, client_id, client_secret):
        self.client = ConfidentialAppAuthClient(client_id, client_secret)
        self.client_id = client_id
        
    def list_all_scopes(self):
        r = self.client.get("/v2/api/scopes")
        return r.text

    def list_scope(self, scope):
        r = self.client.get("/v2/api/scopes/{s}".format(s=scope))
        return r.text

    def create_scope(self, scope):
        # if "scope" is a dict, use it. Otherwise, see if it's a json string or a file containing json.
        if not isinstance(scope, dict):
            try:
                scope = json.loads(scope)
            except ValueError:
                # if this fails, we have nothing left to try, so don't bother catching errors
                f = open(scope, 'r')
                scope = json.load(f)
                f.close()
                
        r = self.client.post("/v2/api/clients/{client_id}/scopes".format(client_id = self.client_id),
                             json_body=scope)
        return r.text

    def add_fqdn_to_client(self, fqdn):
        r = self.client.post('/v2/api/clients/{client_id}/fqdns'.format(client_id=self.client_id),
                             json_body={'fqdn':fqdn})
        return r.text

    def get_clients(self):
        r = self.client.get('/v2/api/clients')
        return r.text


    def verify_access_token(self, token):
        r = self.client.oauth2_validate_token(token)
        return r.text

    def introspect_access_token(self, token):
        r = self.client.oauth2_token_introspect(token)
        return r.text

if __name__ == '__main__':
#    scope_file = sys.argv[1]
#    token = sys.argv[1]    
    s = GlobusClientUtil()
    print s.get_clients()
#    print s.create_scope(scope_file)
#    print s.add_fqdn_to_client('nih-commons.derivacloud.org')
#    print s.list_all_scopes()
#    print s.verify_access_token(token)
#    print s.introspect_access_token(token)    
