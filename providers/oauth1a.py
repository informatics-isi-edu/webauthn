
# 
# Copyright 2012 University of Southern California
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
Webauthn2 oauth 1.0a provider implementations.

Oauth1aSessionIdProvider
   : Implements session identifiers as HTTP in web.py

Provider-specific parameters for oauth1a module:

oauth1a_use_input
   : whether web.input() should be consulted for POST query params (boolean, default None).

"""

from providers import *
from webauthn2.util import *
import web
import oauth.oauth
import random
import sys
import traceback
from database import DatabaseSessionStateProvider, DatabaseClientProvider, \
    DatabaseLogin, DatabaseClientSearch, DatabaseClientManage, DatabaseClientPasswd

config_built_ins = web.storage(
    oauth1a_use_input= False,
    oauth1a_realm= ''
)

__all__ = [
    'Oauth1aSessionIdProvider',
    'OAuth1aSessionStateProvider',
    'config_built_ins'
    ]

class Oauth1aSessionIdProvider (SessionIdProvider):
    """
    Oauth1aSessionIdProvider implements HTTP oauth 1.0a session identifiers.

    """
    
    key = 'oauth1a'
    
    def __init__(self, config):
        SessionIdProvider.__init__(self, config)

    def get_request_sessionids(self, manager, context, db=None):
        """
        Get OAuth request information from web request context.

        It can derive session parameters from:
        -- HTTP Auth headers
        -- HTTP request query parameters 
           -- x-www-urlencoded POST content
           -- URL query parameters for GET etc.

        The session ID will be a discovered oauth_token key.

        As a side-effect, sets context.oauth_request with an instance
        of oauth.OAuthRequest, for use by other providers.

        NOTE: The oauth token is not validated yet, since we do not
        have access to state including nonces or client secrets at
        this point!

        """
        oauth_request = None
        if 'env' in web.ctx:
            http_method = web.ctx.method
            http_url = web.ctx.homedomain + web.ctx.env['REQUEST_URI']
            query_string = web.ctx.query
            if bool(manager.config.get('oauth1a_use_input', False)):
                parameters = web.input()
            else:
                parameters = None
            headers = {
                'Authorization': web.ctx.env.get('HTTP_AUTHORIZATION', '')
                }

            oauth_request = oauth.oauth.OAuthRequest.from_request(http_method, 
                                                                  http_url,
                                                                  headers, 
                                                                  parameters,
                                                                  query_string)

        context.oauth_request = oauth_request
        if oauth_request and oauth_request.parameters \
                and 'oauth_token' in oauth_request.parameters:
            return [ oauth_request.parameters['oauth_token'] ]
        else:
            return []
            
    def create_unique_sessionids(self, manager, context, db=None):
        raise NotImplementedError()

class Oauth1aDataStore (object):
    """
    Implement shim between provide code and oauth.oauth.OAuthServer class.

    """
    def __init__(self, session):
        self.session = session

    def lookup_consumer(self, consumer_key):
        return oauth.oauth.OAuthConsumer(consumer_key, self.session.client_secret)

    def lookup_token(self, token_type, token_field):
        if token_field == self.session.keys[0] \
                and token_type == self.session.token_type:
            return oauth.oauth.OAuthToken(token_field, self.session.secret)
        else:
            return None

    def lookup_nonce(self, consumer, token, nonce):
        # TODO: implement nonce storage
        return None


class Oauth1aSessionStateProvider (DatabaseSessionStateProvider):
    """
    Oauth1aSessionStateProvider stores token properties as part of session.

    The standardized context metadata includes:

       context.client:                the consumer key
       context.session.client_secret: the secret corresponding to the consumer key
       context.session.token_type:    'access'
       context.session.keys[0]:       the token
       context.session.secret:        the secret corresponding to the token
       context.session.aux:           app-specific metadata

    This provider adds an 'aux' web.Storage object to the session,
    which apps or derived classes can augment with more metadata which
    will all be persisted and restored with the session.

    It is up to derived classes to produce new context/session state
    which can then be persisted by this provider.

    """

    key = 'oauth1a'
    storage_name = 'oauth_tokens'
    extra_columns = [ ('token_type', 'text'),
                      ('secret', 'text'),
                      ('client_secret', 'text'),
                      ('aux_json', 'text') ]

    def __init__(self, config):
        DatabaseSessionStateProvider.__init__(self, config)

    def set_msg_context(self, manager, context, sessionids, db=None):
        """
        Load existing session state keyed by sessionids, e.g. the access token value.

        """
        if not hasattr(context, 'oauth_request') or context.oauth_request == None:
            return

        def db_body(db):

            srow = DatabaseSessionStateProvider.set_msg_context(self, manager, context, sessionids, db)

            if srow:
                # set oauth-related extensions on context
                context.session.token_type = srow.token_type
                context.session.secret = srow.secret
                context.session.client_secret = srow.client_secret

                if srow.aux_json != None:
                    aux = jsonReader(srow.aux_json)
                else:
                    aux = None

                context.session.aux = aux

                data_store = Oauth1aDataStore(context.session)
                oauth_server = oauth.oauth.OAuthServer(data_store)
                oauth_server.add_signature_method(oauth.oauth.OAuthSignatureMethod_HMAC_SHA1())
    
                try:
                    oauth_server.verify_request(context.oauth_request)
                except oauth.oauth.OAuthError, te:
                    if hasattr(te, 'message'):
                        web.debug(te.message)
                    # clear session-related state on invalid signature
                    context.oauth_request = None
                    context.client = None
                    context.attributes = set()
                    context.session = None

        if db:
            return db_body(db)
        else:
            return self._db_wrapper(db_body)

    def _new_session_extras(self, manager, context, db):
        """
        Generate extra (column, value) pairs for INSERT of new session.

        """
        # return oauth-related extensions from context
        return [ ('token_type', context.session.token_type),
                 ('secret', context.session.secret),
                 ('client_secret', context.session.client_secret),
                 ('aux_json', jsonWriter(context.session.aux)) ]

