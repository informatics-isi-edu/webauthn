
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
Webauthn2 provider implementations using the Globus goauth protocol. Globus encodes user identity information into their
OAuth2 bearer tokens and provides an interface to extract that information.
"""


from providers import *
from webauthn2.util import *
from webauthn2.providers import database

import web

import random
import urllib
import urllib2
import uuid
import urlparse
import web
import simplejson
import psycopg2
import oauth2client.client
from jwkest import jwk
from jwkest import jws
from oauth2client.crypt import AppIdentityError, _urlsafe_b64decode, CLOCK_SKEW_SECS, AUTH_TOKEN_LIFETIME_SECS, MAX_TOKEN_LIFETIME_SECS, PyCryptoVerifier
import time
import base64
from Crypto import Random
from Crypto.Hash.HMAC import HMAC
import Crypto.Hash.SHA256
import json
from datetime import datetime, timedelta
import webauthn2.providers
import collections
import yaml
import oauth2
from nexus import GlobusOnlineRestClient


config_built_ins = web.storage(
    # Items needed for methods inherited from database provider
    database_type= 'postgres',
    database_dsn= 'dbname=',
    database_schema= 'webauthn2',
    database_max_retries= 5,
    oauth2_redirect_relative_uri="/authn/session",
    oauth2_nonce_cookie_name='oauth2_auth_nonce',
    # GOAuth-specific config parameters.
    # File with shared secret, etc., read by nexus api calls
    goauth_config_file='/usr/local/etc/goauth/go_config.yml',
    # GOAuth endpoint for auth requests
    goauth_endpoint_protocol='https',
    goauth_endpoint_server='www.globus.org',
    goauth_endpoint_path = '/OAuth',
    goauth_redirect_relative_uri="/authn/session"
    )

__all__ = [
    'GOAuthClientProvider',
    'config_built_ins'
    ]


class GOAuth (database.DatabaseConnection2):

    # this is the storage format version, not the software version
    major = 1
    minor = 0

    def __init__(self, config):
        database.DatabaseConnection2.__init__(self, config)

class GOAuthLogin(ClientLogin):
    def __init__(self, provider):
        ClientLogin.__init__(self, provider)

    def login(self, manager, context, db, **kwargs):
        """
        Return "username" in the form iss:sub.

        It is expected that the caller will store the resulting username into context.client for reuse.
        
        """

        vals = web.input()
        # Globus doesn't forward "scope" parameters, so no nonce checking here.
        go = GlobusOnlineRestClient(config_file=self.provider.cfg.get('goauth_config_file'))
        base_timestamp = datetime.now()
        my_uri = web.ctx.home + web.ctx.path
        web.debug("passing {my_uri} as referrer_uri".format(my_uri = my_uri))
        try:
            access_token, refresh_token, expires_in = go.goauth_get_access_token_from_code(vals.get('code'), my_uri)
        except TypeError:
            web.debug("old version of globus library, trying old goauth_get_access_token_from_code")
            access_token, refresh_token, expires_in = go.goauth_get_access_token_from_code(vals.get('code'))
        # Temporary for Kyle -- print access token
        web.debug("Globus access token: '{access_token}'".format(access_token=access_token))
        username, client_id, server = go.goauth_validate_token(access_token)
        context.user['access_token'] = access_token
        context.user['refresh_token'] = refresh_token
        context.user['access_token_expiration'] = base_timestamp + timedelta(seconds=int(expires_in))
        
        # Get Globus client for authenticated user
        user_config = {"server" : go.config["server"], "client" : username, "client_secret" : None, "goauth_token" : access_token}
        user_client = GlobusOnlineRestClient(config=user_config)
        userinfo = user_client.get_user(username)
        context.user['userinfo'] =  simplejson.dumps(userinfo, separators=(',', ':'))
        
        group_ids = []
        response, content = user_client.get_group_list(my_roles=["manager","admin","member"])
        if response["status"] == "200":
            group_ids = [g["id"] for g in content if g["my_status"] == "active"]
        context.goauth_groups = set(group_ids)

        if self.provider._client_exists(db, username):
            manager.clients.manage.update_noauthz(manager, context, username, db)
        else:
            context.user['username'] = username
            manager.clients.manage.create_noauthz(manager, context, username, db)

        return username

    def accepts_login_get(self):
        return True

    def login_keywords(self, optional=False):
        return set()


class GOAuthPreauthProvider (oauth2.OAuth2PreauthProvider):
    key = 'goauth'


    def __init__(self, config):
        oauth2.OAuth2PreauthProvider.__init__(self, config)
        self.nonce_state = oauth2.nonce_util(config)
        self.nonce_cookie_name = config.oauth2_nonce_cookie_name
        self.cfg=GOAuthConfig(config)
        self.authentication_uri_base = [
        self.cfg.get('goauth_endpoint_protocol'),
        self.cfg.get('goauth_endpoint_server'),
        self.cfg.get('goauth_endpoint_path')]

        self.authentication_uri_args = {
            "client_id" : self.cfg.get("client"),
            "response_type" : "code"
#            "response_mode" : "form_post"
        }

class GOAuthClientProvider (oauth2.OAuth2ClientProvider):

    key = 'goauth'
    client_storage_name = 'user'
    extra_client_columns = [('userinfo', 'json'),
                            ('access_token', 'text'),
                            ('access_token_expiration', 'timestamp'),
                            ('refresh_token', 'text')]  # list of (columnname, typestring) pairs
    summary_storage_name = 'usersummary'
    
    # data storage format version
    major = 1
    minor = 0

    def __init__(self, config, 
                 Login=GOAuthLogin,
                 Search=database.DatabaseClientSearch,
                 Manage=oauth2.OAuth2ClientManage,
                 Passwd=None):
        ClientProvider.__init__(self, config)
        self.cfg=GOAuthConfig(config)
        database.DatabaseConnection2.__init__(self, config)
        self.login = Login(self)
        self.search = Search(self)
        self.manage = Manage(self)
        if Passwd:
            self.passwd = Passwd(self)
        self.nonce_state = oauth2.nonce_util(config)
        self.cfg = oauth2.OAuth2Config(config)
        self.nonce_cookie_name = config.oauth2_nonce_cookie_name
        self.provider_sets_token_nonce = config.oauth2_provider_sets_token_nonce



class GOAuthConfig(oauth2.OAuth2Config):
    def __init__(self, config):
        self.dictionaries = [self.load_goauth_config_file(config),
                             config]

    def load_goauth_config_file(self, config):
        if config.goauth_config_file == None:
            raise oauth2.OAuth2ConfigurationError("No goauth yml file configured")
        f = open(config.goauth_config_file)
        d=yaml.load(f)
        f.close()
        return d


class GOAuthAttributeClient (AttributeClient):

    def __init__(self, provider):
        AttributeClient.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        if hasattr(context, 'goauth_groups'):
            context.attributes.update(["g:" + group for group in context.goauth_groups])

class GOAuthAttributeProvider (database.DatabaseAttributeProvider):

    key = 'goauth'

    def __init__(self, config):
        database.DatabaseAttributeProvider.__init__(self, config)
        self.client = GOAuthAttributeClient(self)

