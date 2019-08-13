
# 
# Copyright 2012-2016 University of Southern California
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

import sys
import webauthn2
import web

webauthn2_manager = webauthn2.Manager()

# expose webauthn REST APIs
webauthn2_handler_factory = webauthn2.RestHandlerFactory(manager=webauthn2_manager)
UserSession = webauthn2_handler_factory.UserSession
UserPassword = webauthn2_handler_factory.UserPassword
UserManage = webauthn2_handler_factory.UserManage
AttrManage = webauthn2_handler_factory.AttrManage
AttrAssign = webauthn2_handler_factory.AttrAssign
AttrNest = webauthn2_handler_factory.AttrNest
Preauth = webauthn2_handler_factory.Preauth
Discovery = webauthn2_handler_factory.Discovery

def web_urls():
    """Builds and returns the web_urls for web.py.
    """
    urls = (
        # user authentication via webauthn2
        '/session(/[^/]+)', UserSession,
        '/session/?()', UserSession,
        '/password(/[^/]+)', UserPassword,
        '/password/?()', UserPassword,
    
        # user account management via webauthn2
        '/user(/[^/]+)', UserManage,
        '/user/?()', UserManage,
        '/attribute(/[^/]+)', AttrManage,
        '/attribute/?()', AttrManage,
        '/user/([^/]+)/attribute(/[^/]+)', AttrAssign,
        '/user/([^/]+)/attribute/?()', AttrAssign,
        '/attribute/([^/]+)/implies(/[^/]+)', AttrNest,
        '/attribute/([^/]+)/implies/?()', AttrNest,
        '/preauth(/[^/]+)', Preauth,
        '/preauth/?()', Preauth,
        '/discovery(/[^/]+)', Discovery,
        '/discovery/?()', Discovery,	
    )
    return tuple(urls)


# this creates the WSGI app using the web_urls map and the web.py framework
application = web.application(web_urls(), globals()).wsgifunc()

