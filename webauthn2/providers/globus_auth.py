
# 
# Copyright 2010-2023 University of Southern California
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

import base64
import urllib
import json

from .providers import *
from ..util import *
from . import database
from . import oauth2

USE_GLOBUS_SDK = False
try:
    import globus_sdk
    USE_GLOBUS_SDK = True
except:
    pass

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

class GlobusGroupTokenProcessor(oauth2.GroupTokenProcessor):
    default_accepted_roles=['admin', 'manager', 'member']
    def __init__(self, issuer, expected_scopes, group_base_url, accepted_roles=None):
        oauth2.GroupTokenProcessor.__init__(self, expected_scopes)
        self.issuer = issuer
        self.accepted_roles = accepted_roles if accepted_roles else self.default_accepted_roles
        self.group_base_url = group_base_url
        self.token = None

    def set_token(self, token):
        self.token = token

    def get_raw_groups(self, group_request):
        group_request.add_header('Authorization', 'Bearer ' + self.token.get('access_token'))
        u = oauth2.OAuth2Login.open_url(group_request, "getting groups")
        raw_groups = json.load(u)
        u.close()
        return(raw_groups)

    def get_groups(self):
        raise NotImplementedError()

    def make_group(self, id, name):
        return KeyedDict({ID : self.issuer + "/" + id,
                          DISPLAY_NAME : name})    
        

class GlobusViewGroupTokenProcessor(GlobusGroupTokenProcessor):
    default_base_url = "https://groups.api.globus.org/v2/groups/my_groups"
    def __init__(self, issuer, group_base_url=None):
        GlobusGroupTokenProcessor.__init__(self, issuer,
                                           ["urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships"],
                                           group_base_url if group_base_url else self.default_base_url)

    def get_groups(self):
 #       deriva_debug("trying view_my_groups, token is {t}".format(t=str(self.token)))
        final_groups = set()
        if self.token != None:
            group_request = urllib.request.Request(self.group_base_url)
            raw_groups = self.get_raw_groups(group_request)
            
            for g in raw_groups:
                # Unlike the old API, this will only return
                # "groups in which the user is an active member, manager, or admin"
                # so no need to descend into memberships and check status/role
                
                final_groups.add(self.make_group(g["id"], g.get("name")))                
        return final_groups
        

class GlobusLegacyGroupTokenProcessor(GlobusGroupTokenProcessor):
    default_base_url="https://nexus.api.globusonline.org/groups"    
    def __init__(self, issuer, group_base_url=None, accepted_roles=None):
        GlobusGroupTokenProcessor.__init__(self, issuer,
                                           ["urn:globus:auth:scope:nexus.api.globus.org:groups"],
                                           group_base_url if group_base_url else self.default_base_url,
                                           accepted_roles=accepted_roles)
        self.group_args = {
            'include_identity_set_properties' : 'true',
            'my_roles' : ','.join(self.accepted_roles),
            'my_statuses' : 'active',
            'for_all_identities' : 'true'
        }

    def get_groups(self):
#        deriva_debug("Using legacy Globus group processor")
        final_groups = set()
        if self.token != None:
            urltuple = urllib.parse.urlsplit(self.group_base_url)
            group_request = urllib.request.Request(urllib.parse.urlunsplit([urltuple[0], urltuple[1], urltuple[2], urllib.parse.urlencode(self.group_args), None]))
            raw_groups = self.get_raw_groups(group_request)
            for g in raw_groups:
                group = self.make_group(g["id"], g.get("name"))
                if g["my_status"] == "active":
                    final_groups.add(group)
                else:
                    idprops = g.get("identity_set_properties")
                    if idprops != None:
                        for props in idprops.values():
                            if props.get("role") in self.accepted_roles and props.get("status") == "active":
                                final_groups.add(group)
                                break
        return(final_groups)
        

class GlobusAuthLogin(oauth2.OAuth2Login):
    
    def login(self, manager, context, conn, cur, **kwargs):
        user_id = oauth2.OAuth2Login.login(self, manager, context, conn, cur, **kwargs)
        other_tokens = self.payload.get('other_tokens')
        dependent_tokens = self.payload.get('dependent_tokens')
        dependent_tokens_source = self.payload.get('dependent_tokens_source')
        group_base = self.provider.cfg.get('globus_auth_group_endpoint')
        group_token_processor = None
        context.globus_identities = set()
        context.globus_identities.add(user_id)
        identity_set = self.userinfo.get('identities_set')
        issuer = self.userinfo.get('iss')
        all_group_processors = [
            GlobusViewGroupTokenProcessor(group_base_url=group_base, issuer=issuer),
            GlobusLegacyGroupTokenProcessor(group_base_url=group_base, issuer=issuer)
        ]
        context.client[IDENTITIES] = []
        if identity_set != None:
            for id in identity_set:
                full_id = issuer + '/' + id
                context.globus_identities.add(KeyedDict({ID : full_id}))
                context.client[IDENTITIES].append(full_id)

        if other_tokens != None:
            for token in other_tokens:
                self.add_to_wallet(context, issuer, token)
                if group_token_processor is None:
                    for processor in all_group_processors:
                        if processor.token_recognized(token):
                            processor.set_token(token)
                            group_token_processor = processor

        if dependent_tokens != None:
            for token in dependent_tokens:
                self.add_to_wallet(context, issuer, token)
                if group_token_processor is None:
                    for processor in all_group_processors:
                        if processor.token_recognized(token):
                            processor.set_token(token)
                            group_token_processor = processor
                    
#        deriva_debug("wallet: " + str(context.wallet))
#        deriva_debug("token processor: " + str(group_token_processor))
        if group_token_processor is not None:
            context.globus_groups = group_token_processor.get_groups()
            
        self.provider.manage.update_last_login(manager, context, context.client[ID], conn, cur)
        self.provider.manage.update_last_group_update(manager, context, context.client[ID], conn, cur)
        return context.client

    def add_extra_token_request_headers(self, token_request):
        client_id = self.provider.cfg.get('client_id')
#        deriva_debug("client id is {i}".format(i=client_id))
        client_secret = self.provider.cfg.get('client_secret')
        basic_auth_token = base64.b64encode((client_id + ':' + client_secret).encode())
        token_request.add_header('Authorization', 'Basic ' + basic_auth_token.decode())

    def make_userinfo_request(self, endpoint, access_token):
        req = urllib.request.Request(endpoint, urllib.parse.urlencode({'token' : access_token, 'include' : 'identities_set'}).encode())
        self.add_extra_token_request_headers(req)
        return req

    def payload_from_bearer_token(self, bearer_token, context, conn, cur):
        oauth2.OAuth2Login.payload_from_bearer_token(self, bearer_token, context, conn, cur)
        if USE_GLOBUS_SDK:
            client = globus_sdk.ConfidentialAppAuthClient(self.provider.cfg.get('client_id'), self.provider.cfg.get('client_secret'))            
            # attempt to get dependent tokens
            try:
#                introspect_response = client.oauth2_token_introspect(bearer_token)
                token_response = client.oauth2_get_dependent_tokens(bearer_token).data
                if token_response != None and len(token_response) > 0:
                    self.payload['dependent_tokens_source'] = client.base_url
                    if self.payload['dependent_tokens_source'].endswith('/'):
                        self.payload['dependent_tokens_source'] = self.payload['dependent_tokens_source'][:-1]
                    if self.payload.get('dependent_tokens') == None:
                        self.payload['dependent_tokens'] = dict()
                    self.payload['dependent_tokens'] = token_response
            except globus_sdk.exc.AuthAPIError as ex:
                deriva_debug("WARNING: dependent token request returned {ex}".format(ex=ex))
        else:
            deriva_debug("WARNING: No globus_sdk installed; skipping dependent token request. This means no group info and an empty wallet for sessions authenticated by bearer token.")
    
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

    def set_msg_context(self, manager, context, conn=None, cur=None):
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

    def terminate(self, manager, context, conn=None, cur=None, preferred_final_url=None):
        globus_args = ['client_id', 'redirect_name']
        oauth2.OAuth2SessionStateProvider.terminate(self, manager, context, conn, cur)
        logout_base = self.cfg.get('revocation_endpoint')
        if logout_base is None:
            raise oauth2.OAuth2ConfigurationError("No revocation endpoint configured")
        rest_args = web_input()
        args=dict()
        for key in globus_args:
            val=rest_args.get('logout_' + key)
            if val == None:
                val = self.cfg.get(self.key + '_logout_' + key)
            if val != None:
                args[key] = val
        if preferred_final_url is not None:
            args['redirect_uri'] = preferred_final_url
        globus_logout_url = logout_base + "?" + urllib.parse.urlencode(args)
        return {LOGOUT_URL: globus_logout_url}
