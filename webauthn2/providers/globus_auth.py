
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
    def add_extra_token_request_headers(self, token_request):
        client_id = self.provider.cfg.get('client_id')
        client_secret = self.provider.cfg.get('client_secret')
        web.debug('auth string = "' + client_id + ':' + client_secret + '"')
        basic_auth_token = base64.b64encode(client_id + ':' + client_secret)
        web.debug('basic_auth_token = "' + basic_auth_token + '"')
        token_request.add_header('Authorization', 'Basic ' + basic_auth_token)
        web.debug("token_request url: " + token_request.get_full_url())
        web.debug("token_request Authorization headers: " + str(token_request.header_items()))
        web.debug("token_request data: " + str(token_request.get_data()))

    def make_userinfo_request(self, endpoint, access_token):
        req = urllib2.Request(endpoint, data=urllib.urlencode({'token' : access_token}))
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
