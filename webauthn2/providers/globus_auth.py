
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
    major = 1
    minor = 0

    def __init__(self, config):
        database.DatabaseConnection2.__init__(self, config)

class GlobusAuthLogin(oauth2.OAuth2Login):
    def login(self, manager, context, db, **kwargs):
        username = oauth2.OAuth2Login.login(self, manager, context, db, **kwargs)
        other_tokens = self.payload.get('other_tokens')
        if other_tokens == None:
            return username
        group_token = None
        context.globus_identities = set([username])
        identity_set = self.userinfo.get('identities_set')
        issuer = self.id_token.get('iss')
        if identity_set != None:
            for id in identity_set:
                context.globus_identities.add(issuer + '/' + id)
        for token in other_tokens:
            scope = token.get('scope')
            if scope is not None:
                self.add_to_wallet(context, scope, issuer, token)
            if scope == "urn:globus:auth:scope:nexus.api.globus.org:groups":
                group_token = token
                break
        web.debug("wallet: " + str(context.wallet))
        if group_token == None:
            return username
        group_args = {
            'include_identity_set_properties' : 'true',
            'my_roles' : 'admin,manager,member',
            'my_statuses' : 'active',
            'for_all_identities' : 'true'
            }
        group_endpoint = urlparse.urlunsplit(["https", 'nexus.api.globusonline.org', "groups", urllib.urlencode(group_args), None])
        token_request = urllib2.Request(group_endpoint)
        token_request.add_header('Authorization', 'Bearer ' + group_token.get('access_token'))
        u = self.open_url(token_request, "getting groups", False)
        groups = simplejson.load(u)
        u.close()
        context.globus_groups = set()
        for g in groups:
            if g["my_status"] == "active":
                context.globus_groups.add(issuer + "/" + g["id"])
        for g in groups:
            if g.get('identity_set_properties') != None:
                for k in g.get('identity_set_properties').keys():
                    context.globus_identities.add(issuer + '/' +  k)
        return username

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

    def make_uri(self, relative_uri):
        override_uri = self.cfg.get('globus_auth_override_full_redirect_uri')
        if override_uri is not None and override_uri != '':
            return override_uri
        else:
            return oauth2.OAuth2PreauthProvider.make_uri(self, relative_uri)

class GlobusAuthAttributeClient (AttributeClient):

    def __init__(self, provider):
        AttributeClient.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        if hasattr(context, 'globus_groups'):
            context.attributes.update([group for group in context.globus_groups])
        context.attributes.update(identity for identity in context.globus_identities)

class GlobusAuthAttributeProvider (database.DatabaseAttributeProvider):

    key = 'globus_auth'

    def __init__(self, config):
        database.DatabaseAttributeProvider.__init__(self, config)
        self.client = GlobusAuthAttributeClient(self)
