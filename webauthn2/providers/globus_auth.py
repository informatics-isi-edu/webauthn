
# 
# Copyright 2010-2012 University of Southern California
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
Globus flavor of OAuth2. They require HTTP Basic authentication for token requests, and also provide group management.
"""

from providers import *
from webauthn2.util import *
from webauthn2.providers import database
import oauth2
import base64
import urllib2
import urllib
import urlparse
import json

import web

__all__ = [
    'GlobusAuthClientProvider',
    'config_built_ins'
    ]


class GlobusAuth (database.DatabaseConnection2):

    # this is the storage format version, not the software version
    major = 2
    minor = 0

    def __init__(self, config):
        database.DatabaseConnection2.__init__(self, config)

class GlobusAuthLogin(oauth2.OAuth2Login):
    def login(self, manager, context, db, **kwargs):
        user_id = oauth2.OAuth2Login.login(self, manager, context, db, **kwargs)
        other_tokens = self.payload.get('other_tokens')
        if other_tokens == None:
            return user_id
        group_token = None
        context.globus_identities = set()
        context.globus_identities.add(user_id)
        identity_set = self.userinfo.get('identities_set')
        issuer = self.id_token.get('iss')
        context.client[IDENTITIES] = []
        if identity_set != None:
            for id in identity_set:
                full_id = issuer + '/' + id
                context.globus_identities.add(KeyedDict({ID : full_id}))
                context.client[IDENTITIES].append(full_id)

        for token in other_tokens:
            scope = token.get('scope')
            if scope is not None:
                self.add_to_wallet(context, scope, issuer, token)
            if scope == "urn:globus:auth:scope:nexus.api.globus.org:groups":
                group_token = token
        #web.debug("wallet: " + str(context.wallet))
        if group_token == None:
            return user_id
        accepted_roles = ['admin', 'manager', 'member']
        group_args = {
            'include_identity_set_properties' : 'true',
            'my_roles' : ','.join(accepted_roles),
            'my_statuses' : 'active',
            'for_all_identities' : 'true'
            }
        group_base = self.provider.cfg.get('globus_auth_group_endpoint')
        if group_base == None:
            group_base = "https://nexus.api.globusonline.org/groups"
        urltuple = urlparse.urlsplit(group_base)
        token_request = urllib2.Request(urlparse.urlunsplit([urltuple[0], urltuple[1], urltuple[2], urllib.urlencode(group_args), None]))
        token_request.add_header('Authorization', 'Bearer ' + group_token.get('access_token'))
        u = self.open_url(token_request, "getting groups", False)
        groups = simplejson.load(u)
        u.close()
#        web.debug("groups: " + str(groups))
        context.globus_groups = set()
        for g in groups:
            group = KeyedDict({ID : issuer + "/" + g["id"],
                               DISPLAY_NAME : g.get('name')})
            if g["my_status"] == "active":
                context.globus_groups.add(group)
            else:
                idprops = g.get("identity_set_properties")
                if idprops != None:
                    for props in idprops.values():
                        if props.get("role") in accepted_roles and props.get("status") == "active":
                            context.globus_groups.add(group)
                            break
        self.provider.manage.update_last_login(manager, context, context.client[ID], db)
        self.provider.manage.update_last_group_update(manager, context, context.client[ID], db)
        return context.client

    def add_extra_token_request_headers(self, token_request):
        client_id = self.provider.cfg.get('client_id')
        client_secret = self.provider.cfg.get('client_secret')
        basic_auth_token = base64.b64encode(client_id + ':' + client_secret)
        token_request.add_header('Authorization', 'Basic ' + basic_auth_token)

    def make_userinfo_request(self, endpoint, access_token):
        req = urllib2.Request(endpoint)
        req.add_data(urllib.urlencode({'token' : access_token, 'include' : 'identities_set'}))
        self.add_extra_token_request_headers(req)
        return req

# Sometimes Globus whitelist entries will have typos in the URLs ("//" instead of "/" is very common),
# and it can take a long time to get those fixed.

    def my_uri(self):
        override_uri = self.provider.cfg.get('globus_auth_override_full_redirect_uri')
        if override_uri is not None and override_uri != '':
            return override_uri
        else:
            return oauth2.OAuth2Login.my_uri(self)


class GlobusAuthClientProvider (oauth2.OAuth2ClientProvider):

    key = 'globus_auth'

    def __init__(self, config, 
                 Login=GlobusAuthLogin,
                 Search=database.DatabaseClientSearch,
                 Manage=oauth2.OAuth2ClientManage,
                 Passwd=None):
        oauth2.OAuth2ClientProvider.__init__(self, config, Login, Search, Manage, Passwd)


class GlobusAuthPreauthProvider (oauth2.OAuth2PreauthProvider):

    key = 'globus_auth'

# Sometimes Globus whitelist entries will have typos in the URLs ("//" instead of "/" is very common),
# and it can take a long time to get those fixed.

    def make_relative_uri(self, relative_uri):
        override_uri = self.cfg.get('globus_auth_override_full_redirect_uri')
        if override_uri is not None and override_uri != '':
            return override_uri
        else:
            return oauth2.OAuth2PreauthProvider.make_relative_uri(self, relative_uri)

class GlobusAuthAttributeClient (AttributeClient):

    def __init__(self, provider):
        AttributeClient.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        if hasattr(context, 'globus_groups'):
            context.attributes.update(group for group in context.globus_groups)
        context.attributes.update(identity for identity in context.globus_identities)

class GlobusAuthAttributeProvider (database.DatabaseAttributeProvider):
    """
    Globus groups and multiple identities
    """

    key = 'globus_auth'

    def __init__(self, config):
        database.DatabaseAttributeProvider.__init__(self, config)
        self.client = GlobusAuthAttributeClient(self)

class GlobusAuthSessionStateProvider(oauth2.OAuth2SessionStateProvider):
    """
    OAuth2 session state plus Globus logout
    """

    key = 'globus_auth'

    def terminate(self, manager, context, db=None, preferred_final_url=None):
        globus_args = ['client_id', 'redirect_name']
        oauth2.OAuth2SessionStateProvider.terminate(self, manager, context, db)
        logout_base = self.cfg.get('revocation_endpoint')
        if logout_base == None:
            raise oauth2.OAuth2ConfigurationError("No revocation endpoint configured")
        rest_args = web.input()
        args=dict()
        for key in globus_args:
            val=rest_args.get('logout_' + key)
            if val == None:
                val = self.cfg.get(self.key + '_logout_' + key)
            if val != None:
                args[key] = val
        if preferred_final_url != None:
            args['redirect_uri'] = preferred_final_url
        globus_logout_url = logout_base + "?" + urllib.urlencode(args)
        retval = dict()
        retval[LOGOUT_URL] = globus_logout_url
        return retval
