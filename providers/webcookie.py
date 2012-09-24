
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
Webauthn2 webcookie provider implementation.

WebcookieSessionIdProvider
   : Implements session identifiers as HTTP cookies in web.py

test_cookies
   : Used in place of web cookies when web.ctx.env is absent, for testing.

Provider-specific parameters for webcookie module:

`web_cookie_name`
   : The name of the cookie to use when storing session identifiers in HTTP clients (text).

`web_cookie_secure`
   : Whether the cookie is marked as a secure cookie (boolean).

`web_cookie_path`
   : The server path used to limit the scope of the cookie (text).

"""

from providers import *
from webauthn2.util import *
import web

import random

config_built_ins = web.storage(
    web_cookie_name= 'webauthn2',
    web_cookie_secure= True,
    web_cookie_path= '/'
)

test_cookies = web.storage()

__all__ = [
    'generate_sessguid',
    'WebcookieSessionIdProvider',
    'config_built_ins',
    'test_env'
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

    def get_request_sessionids(self, manager, context, db=None):
        if 'env' in web.ctx:
            cookie = web.cookies().get(self.cookiename)
        else:
            cookie = test_cookies.get(self.cookiename)

        if cookie:
            # cookie contains sessguid | other data...
            return [ cookie.split('|')[0] ]
        else:
            return []

    def create_unique_sessionids(self, manager, context, db=None):
        context.session.keys = [ generate_sessguid() ]

    def set_request_sessionids(self, manager, context, db=None):
        if len(context.session.keys) > 0:
            cookie = context.session.keys[0]
        else:
            cookie = ''

        if 'env' in web.ctx:
            try:
                # newer web.py needs path or defaults to current URL path
                web.setcookie(self.cookiename,
                              cookie,
                              domain=None,
                              secure=self.secure,
                              path=self.path)
            except TypeError:
                # old web.py doesn't support path keyword
                web.setcookie(self.cookiename,
                              cookie,
                              domain=None,
                              secure=self.secure)
        else:
            test_cookies[self.cookiename] = cookie

