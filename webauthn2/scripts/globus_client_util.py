from globus_sdk import ConfidentialAppAuthClient
import json
import sys
import pprint

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

    def update_scope(self, scope_id, args):
        r = self.client.put("/v2/api/scopes/{scope_id}".format(scope_id = scope_id),
                             json_body={"scope" : args})
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

    def create_private_client(self, name, redirect_uris):
        nih_client_dict = {
            "client" : {
                "name" : name,
                "public_client" : False,
                "redirect_uris" : redirect_uris
                }
        }
        r = self.client.post("/v2/api/clients",
                             json_body = nih_client_dict)
        return r.text

    def add_redirect_uris(self, redirect_uris):
        d={
            "client": {
                "redirect_uris" : redirect_uris
                }
            }
        r = self.client.put("/v2/api/clients/{client_id}".format(client_id=self.client_id),
                            json_body=d)
        return r.text
    
    def get_my_client(self):
        r = self.client.get('/v2/api/clients/{client_id}'.format(client_id=self.client_id))
        return r.text

    def get_scopes_by_name(self, sname_string):
        scopes = self.client.get('/v2/api/scopes?scope_strings={sname}'.format(sname=sname_string))
        if scopes == None:
            return None
        else:
            return scopes.get("scopes")

    def get_scopes_by_id(self, id_string):
        scopes = self.client.get('/v2/api/scopes?ids={ids}'.format(ids=id_string))
        if scopes == None:
            return None
        else:
            return scopes.get("scopes")

    def my_scope_ids(self):
        c = self.client.get('/v2/api/clients/{client_id}'.format(client_id=self.client_id))
        me = c.get("client")
        if me == None or me.get('scopes') == None:
            return []
        else:
            return me.get('scopes')

    def my_scope_names(self):
        snames = []
        scope_ids=self.my_scope_ids()
        if scope_ids != None:
            ids=",".join(scope_ids)
            print(str(ids))
            scopes=self.get_scopes_by_id(ids)
            for s in scopes:
                snames.append(s.get('scope_string'))
        return snames

    def get_grant_types(self):
        grant_types=None
        c = self.client.get('/v2/api/clients/{client_id}'.format(client_id=self.client_id))
        me = c.get("client")
        if me != None:
            grant_types = me.get('grant_types')
        return(grant_types)

    def add_scopes(self, new_scopes):
        scopes=set(self.my_scope_ids())
        for s in self.get_scopes_by_name(",".join(new_scopes)):
            scopes.add(s.get('id'))
        d = {
            "client": {
                "scopes" : list(scopes)
            }
        }


        r=self.client.put('/v2/api/clients/{client_id}'.format(client_id=self.client_id),
                          json_body=d)
        return r.text

    def add_dependent_scopes(self, parent_scope_name, child_scope_names):
        child_scope_ids = set()
        parent_scopes = self.get_scopes_by_name(parent_scope_name)
        if parent_scopes == None:
            return "no parent scope"
        if len(parent_scopes) != 1:
            return "{l} parent scopes: {p}".format(l=str(len(parent_scopes)), p=str(parent_scopes))
        parent_scope_id = parent_scopes[0].get("id")
        for s in parent_scopes[0].get('dependent_scopes'):
            child_scope_ids.add(s.get('id'))
        new_child_scopes = self.get_scopes_by_name(",".join(child_scope_names))
        for s in new_child_scopes:
            child_scope_ids.add(s.get('id'))
        dependent_scopes = []
        for id in child_scope_ids:
            dependent_scopes.append({'scope' : id, 'optional' : False, 'requires_refresh_token' : False})            
        d = {
            "scope" : {
                "dependent_scopes" : dependent_scopes
                }
            }
        print(str(d))
        r = self.client.put('/v2/api/scopes/{i}'.format(i=parent_scope_id),
                            json_body=d)
        return r.text

    def create_scope_with_deps(self, name, description, suffix, dependent_scopes=[], advertised=True, allow_refresh_tokens=True):
        dependent_scope_arg = []
        if len(dependent_scopes) > 0:
            child_scopes=self.get_scopes_by_name(",".join(dependent_scopes))
            for s in child_scopes:
                dependent_scope_arg.append({
                    "scope" : s.get("id"),
                    "optional" : False,
                    "requires_refresh_token" : False
                    })
        scope = {
            "scope" : {
                "name" : name,
                "description" : description,
                "scope_suffix" : suffix,
                "dependent_scopes" : dependent_scope_arg,
                "advertised" : advertised,
                "allows_refresh_tokens": allow_refresh_tokens
                }
            }

        r = self.client.post("/v2/api/clients/{client_id}/scopes".format(client_id = self.client_id),
                             json_body=scope)
        return r.text

    def delete_scope(self, scope_string):
        scopes = self.get_scopes_by_name(scope_string)
        if scopes == None or len(scopes) != 1:
            return "null or multiple scopes"
        scope_id = scopes[0].get('id')
        if scope_id == None:
            return "no scope id"
        r = self.client.delete('/v2/api/scopes/{scope_id}'.format(scope_id = scope_id))
        return r.text

    def get_dependent_scopes(self, scope):
        result = {"scope_string" : scope.get("scope_string"), "dependent_scopes" : []}
        for ds in scope.get("dependent_scopes"):
            ds_id = ds.get('scope')
            ds_info = {"id" : ds_id}
            d = self.get_scopes_by_id(ds_id)
            if d != None:
                ds_info['scope_string'] = d[0].get('scope_string')
            result['dependent_scopes'].append(ds_info)
        return(result)

if __name__ == '__main__':
#    scope_file = sys.argv[1]
#    token = sys.argv[1]    
    s = GlobusClientUtil()
    # s.add_dependent_scopes('https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_test_withdeps',
    #                        ['openid',
    #                         'email',
    #                         'urn:globus:auth:scope:nexus.api.globus.org:groups',
    #                         'https://auth.globus.org/scopes/identifiers.globus.org/create_update'
    #                         ])
    # print s.add_grant_types([
    #     "openid",
    #     "email",
    #     "profile",
    #     "urn:globus:auth:scope:auth.globus.org:view_identities",
    #     "urn:globus:auth:scope:nexus.api.globus.org:groups",
    #     "https://auth.globus.org/scopes/identifiers.globus.org/create_update"
    # ])
#    s.add_scopes(["openid", "email"])
#    print str(s.my_scope_names())
#    print s.update_private_client()
#    pprint.pprint(s.get_scopes_by_name('email,urn:globus:auth:scope:nexus.api.globus.org:groups,urn:globus:auth:scope:transfer.api.globus.org:all'))
#    print s.create_private_client("nih_test_3", ["https://webauthn-dev.isrd.isi.edu/authn/session", "https://nih-commons.derivacloud.org/authn/session"])    
#    print s.get_clients()
#    print s.add_scopes(]
#    print s.get_my_client()
#    print s.add_redirect_uris(["https://webauthn-dev.isrd.isi.edu/authn/session", "https://nih-commons.derivacloud.org/authn/session"])
#    print s.create_scope(scope_file)
#    print s.add_fqdn_to_client('nih-commons.derivacloud.org')
    # print s.create_scope_with_deps('Deriva Services', 'Use Deriva Services', 'deriva_all',
    #                                dependent_scopes = [
    #                                    "openid",
    #                                    "email",
    #                                    "profile",
    #                                    "urn:globus:auth:scope:auth.globus.org:view_identities",
    #                                    "urn:globus:auth:scope:nexus.api.globus.org:groups",
    #                                    "urn:globus:auth:scope:transfer.api.globus.org:all",
    #                                    "https://auth.globus.org/scopes/identifiers.globus.org/create_update"
    #                                    ])
    # print s.delete_scope("https://auth.globus.org/scopes/nih-commons.derivacloud.org/deriva_test_nodeps")
    # print s.delete_scope("https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_test_withdeps")
    # print s.delete_scope("https://auth.globus.org/scopes/nih-commons.derivacloud.org/deriva_test_withdeps")
    # print s.delete_scope("https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_test_3")
    # print s.delete_scope("https://auth.globus.org/scopes/nih-commons.derivacloud.org/deriva_test_3")
    # print s.delete_scope("https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_test_4")
    # print s.delete_scope("https://auth.globus.org/scopes/nih-commons.derivacloud.org/deriva_test_4")    
    print str(s.list_all_scopes())
#    scope = s.get_scopes_by_name("https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_all")[0]
#    pprint.pprint(s.get_dependent_scopes(scope))
#    print s.verify_access_token(token)
#    print s.introspect_access_token(token)
    # print s.update_scope('23b9a3f9-872d-4a40-9c4c-a80a4c61f3bf',
    #                      {"name" : "Use Deriva Services",
    #                       "description" : "Use all Deriva services"
    #                       })
    # print s.update_scope('b892c8a9-2f33-4404-9fe3-6eb9093010c3',
    #                      {"name" : "Use Deriva Services on nih-commons.derivacloud.org",
    #                       "description" : "Use all Deriva services on nih-commons.derivacloud.org"
    #                       })
