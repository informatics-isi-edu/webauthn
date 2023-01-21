
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
Webauthn2 webcookie provider implementation.

WebcookieSessionIdProvider
   : Implements session identifiers as HTTP cookies

Provider-specific parameters for webcookie module:

`web_cookie_name`
   : The name of the cookie to use when storing session identifiers in HTTP clients (text).

`web_cookie_secure`
   : Whether the cookie is marked as a secure cookie (boolean).

`web_cookie_path`
   : The server path used to limit the scope of the cookie (text).

"""

import random
import flask

from .providers import *
from ..util import *

config_built_ins = web_storage(
    web_cookie_name= 'webauthn',
    web_cookie_secure= True,
    web_cookie_path= '/',
    tracking_cookie_name='webauthn_track',
)

__all__ = [
    'generate_sessguid',
    'WebcookieSessionIdProvider',
    'config_built_ins',
    ]

def generate_sessguid():
    """Generate a random key of given length."""
    return generate_random_string(24)

class WebcookieSessionIdProvider (SessionIdProvider):
    """
    WebcookieSessionIdProvider implements HTTP cookie-based session identifiers.

    """
    
    key = 'webcookie'
    
    def __init__(self, config):
        SessionIdProvider(config)
        self.cookiename = config.web_cookie_name
        self.secure = config.web_cookie_secure
        self.path = config.web_cookie_path
        self.trackcookiename = config.tracking_cookie_name

    def get_request_sessionids(self, manager, context, conn=None, cur=None):
        cookie = flask.request.cookies.get(self.cookiename)
        track = flask.request.cookies.get(self.trackcookiename)

        if track:
            context.tracking = track
            
        if cookie:
            # cookie contains sessguid | other data...
            return [ cookie.split('|')[0] ]
        else:
            return []

    def create_unique_sessionids(self, manager, context, conn=None, cur=None):
        context.session.keys = [ generate_sessguid() ]

    def set_request_sessionids(self, manager, context, conn=None, cur=None):
        if len(context.session.keys) > 0:
            cookie = context.session.keys[0]
        else:
            cookie = ''

        self.set_cookie(cookie)

    def set_cookie(self, cookie, expires=None):
        deriva_ctx.deriva_response.set_cookie(
            self.cookiename,
            cookie,
            domain=None,
            secure=self.secure,
            path=self.path,
            expires=expires,
        )

    def terminate(self, manager, context, conn=None, cur=None):
        self.set_cookie("", -1)

    def get_http_vary(self):
        return set([ 'cookie' ])

