# 
# Copyright 2012-2019 University of Southern California
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
Webauthn2 REST library supports dispatch from web.py applications.

A factory model encapsulates an entire webauthn2 security context
Manager instance that can be reused by the per-request message handler
classes expected by web.py:

  webauthn2factory = RestHandlerFactory()

  urls = (
     ...
     '/myapp/session(/[^/]+)',  webauthn2factory.UserSession,
     '/myapp/password(/[^/]+)', webauthn2factory.UserPassword,
     '/myapp/user(/[^/]+)', webauthn2factory.UserManage,
     '/myapp/attribute(/[^/]+)', webauthn2factory.AttrManage,
     '/myapp/user/([^/]+)/attribute(/[^/]+), webauthn2factory.AttrAssign,
     '/myapp/attribute/([^/]+)/implies(/[^/]+), webauthn2factory.AttrNest
  )

These REST handlers use basic form/URI inputs and return only basic
URI or JSON results to support AJAX clients.  An application MAY
expose these REST APIs for where appropriate, including its own
AJAX UI front-end to these features.

The handler base class webauthn2factory.RestHandler can be extended by
an application in order to get an integrated security manager with an
optimized database connection pooling feature:

  class AppHandler (webauthn2factory.RestHandler):

     def __init__(self):
         webauthn2factory.RestHandler.__init__(self)

     def GET(self):
         def db_body(db):
            self.context = self.manager.get_request_context(db=db)
            ... # other application use of db
         return self._db_wrapper(db_body)

But this support class is entirely optional.  An application can also
just use the Manager instance directly in its own message handlers:

  manager = webauthn2factory.manager

  class AppHandler (object):

     def GET(self):
        self.context = manager.get_request_context()

"""

from __future__ import print_function
from .util import *
from .manager import Manager, Context
from .providers import Session
import re
import logging
from logging.handlers import SysLogHandler
import datetime
from datetime import timezone
import struct
import json
import hashlib
from collections import OrderedDict

import web
import traceback
import sys

## setup logger and web request log helpers
logger = logging.getLogger('webauthn')
try:
    # the use of '/dev/log' causes SysLogHandler to assume the availability of Unix sockets
    sysloghandler = SysLogHandler(address='/dev/log', facility=SysLogHandler.LOG_LOCAL1)
except:
    # this fallback allows this file to at least be cleanly imported on non-Unix systems
    sysloghandler = logging.StreamHandler()
syslogformatter = logging.Formatter('%(name)s[%(process)d.%(thread)d]: %(message)s')
sysloghandler.setFormatter(syslogformatter)
logger.addHandler(sysloghandler)
logger.setLevel(logging.INFO)

def get_log_parts(start_time_key, request_guid_key, content_range_key, content_type_key):
    """Generate a dictionary of interpolation keys used by our logging template.

       Arguments:
          start_time_key: key to entry in web.ctx w/ current request start timestamp
          request_guid_key: key to entry in web.ctx w/ current request GUID
          content_range_key: key to entry in web.ctx w/ HTTP range
          content_type_key: key to entry in web.ctx w/ HTTP content type
    """
    now = datetime.datetime.now(timezone.utc)
    elapsed = (now - web.ctx[start_time_key])
    client_identity_obj = web.ctx.webauthn2_context and web.ctx.webauthn2_context.client or None
    parts = dict(
        elapsed = elapsed.seconds + 0.001 * (elapsed.microseconds/1000),
        client_ip = web.ctx.ip,
        client_identity_obj = client_identity_obj,
        reqid = web.ctx[request_guid_key].decode(),
        content_range = web.ctx[content_range_key],
        content_type = web.ctx[content_type_key],
        )
    return parts

def request_trace_json(tracedata, parts):
    """Format one tracedata event as part of a request's audit trail.

       tracedata: a string representation of trace event data
       parts: dictionary of log parts
    """
    od = OrderedDict([
        (k, v) for k, v in [
            ('elapsed', parts['elapsed']),
            ('req', parts['reqid']),
            ('trace', tracedata),
            ('client', parts['client_ip']),
            ('user', parts['client_identity_obj']),
        ]
        if v
    ])
    return json.dumps(od, separators=(', ', ':'))

def prune_excessive_dcctx(dcctx):
    """Heuristically prune content from dcctx to avoid overly long log entries.

       The main variable content is facet or referrer.facet
       descriptions, so limit those.

    """
    max_facet_len = 2000

    def prune_facet(container):
        if 'facet' in container:
            facet = container['facet']
            facet_str = json.dumps(facet, separators=(',', ':'))
            if len(facet_str) > max_facet_len:
                del container['facet']
                container['facet_trunc'] = facet_str[0:max_facet_len]

    if 'referrer' in dcctx:
        referrer = dcctx['referrer']
        if isinstance(referrer, dict):
            prune_facet(referrer)
        else:
            del dcctx['referrer']

    prune_facet(dcctx)
    return dcctx

def request_final_json(parts, extra={}):
    try:
        dcctx = web.ctx.env.get('HTTP_DERIVA_CLIENT_CONTEXT', 'null')
        dcctx = urllib.unquote(dcctx)
        dcctx = prune_excessive_dcctx(json.loads(dcctx))
    except:
        dcctx = None

    od = OrderedDict([
        (k, v) for k, v in [
            ('elapsed', parts['elapsed']),
            ('req', parts['reqid']),
            ('scheme', web.ctx.protocol),
            ('host', web.ctx.host),
            ('status', web.ctx.status),
            ('method', web.ctx.method),
            ('path', web.ctx.env['REQUEST_URI']),
            ('range', parts['content_range']),
            ('type', parts['content_type']),
            ('client', parts['client_ip']),
            ('user', parts['client_identity_obj']),
            ('referrer', web.ctx.env.get('HTTP_REFERER')),
            ('agent', web.ctx.env.get('HTTP_USER_AGENT')),
            ('track', web.ctx.webauthn2_context.tracking),
            ('dcctx', dcctx),
        ]
        if v
    ])
    if len(od.get('referrer', '')) > 1000:
        # truncate overly long URL
        od['referrer_md5'] = hashlib.md5(od['referrer']).hexdigest()
        od['referrer'] = od['referrer'][0:500]

    if web.ctx.webauthn2_context and web.ctx.webauthn2_context.session:
        session = web.ctx.webauthn2_context.session
        if hasattr(session, 'to_dict'):
            session = session.to_dict()
        od['session'] = session

    for k, v in extra.items():
        od[k] = v

    return json.dumps(od, separators=(', ', ':'))
    
def log_parts():
    """Generate a dictionary of interpolation keys used by our logging template."""
    return get_log_parts('webauthn_start_time', 'webauthn_request_guid', 'webauthn_request_content_range', 'webauthn_content_type')

def request_trace(tracedata):
    """Log one tracedata event as part of a request's audit trail.

       tracedata: a string representation of trace event data
    """
    logger.info(request_trace_json(tracedata, log_parts()))

def web_method():
    """Augment web handler method with common service logic."""
    def helper(original_method):
        def wrapper(*args):
            # request context init
            web.ctx.webauthn_request_guid = base64.b64encode( struct.pack('Q', random.getrandbits(64)) )
            web.ctx.webauthn_start_time = datetime.datetime.now(timezone.utc)
            web.ctx.webauthn_request_content_range = None
            web.ctx.webauthn_content_type = None
            web.ctx.webauthn2_manager = args[0]
            web.ctx.webauthn2_context = Context() # set empty context for sanity
            web.ctx.webauthn_request_trace = request_trace

            try:
                # run actual method
                return original_method(*args)
            finally:
                # finalize
                self = args[0]
                if hasattr(self, 'context'):
                    web.ctx.webauthn2_context = self.context

                logger.info( request_final_json(log_parts()) )
        return wrapper
    return helper
    
class RestHandlerFactory (object):
    """
    RestHandlerFactory encapsulates one-time application startup.

    """

    def __init__(self, manager=None, overrides=None, defaults=None):
        """
        Initialize request handler factory, with optional pre-initialized service configuration.

        If manager is not None, it is a pre-constructed instance of
        the webauthn2.Manager class.

        If manager is None, the RestHandler instance constructs its
        own Manager instance, passing overrides and defaults verbatim.

        The REST service layer finds its own configuration within
        manager.config

        """
        if not manager:
            manager = Manager(overrides, defaults)

        session_uri = manager.config.get('handler_uri_usersession', None)
        session_duration = datetime.timedelta(minutes=int(manager.config.get('session_expiration_minutes', 30)))

        class RestHandler (DatabaseConnection):
            """
            RestHandler is a base class suitable for use as a web.py request handler.

            It initializes its self.manager and its parent class
            DatabaseConnection.  Derived application classes must
            implement their own web methods PUT, GET, etc. and
            initialize their own self.context such as:

               self.context = self.manager.get_request_context(db=db)

            if they already have opened a pooled connection, or:

               self.context = self.manager.get_request_context()

            if the handler is not already connecte to the database.

            """
            def __init__(self):
                DatabaseConnection.__init__(self, manager.config)
                self.manager = manager

        class UserSession (RestHandler):
            """
            UserSession is a RESTful login/logout handler.

            Register it at a web.py URI pattern like:

               "your_session_prefix(/?)"
               "your_session_prefix(/[^/]+)"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit session ID prefixed with
            the '/' character.
            
            """
            def __init__(self):
                RestHandler.__init__(self)
                self.session_uri = session_uri
                self.session_duration = session_duration

            @web_method()
            def POST(self, sessionids, storage=None):
                """
                Session start (login) uses POST with form parameters.

                It does not make sense to POST to an existing
                sessionid, only to the session container as a
                whole. We treat implied session IDs, e.g. from
                cookies, the same way.

                We also refuse to support login if the client is
                already authenticated in some manner.

                """
                if sessionids:
                    # trim leading '/'
                    sessionids = sessionids[1:]

                if sessionids:
                    # no POST support for session ID URLs
                    raise NoMethod()

                if not self.manager.clients.login \
                        or not self.manager.sessionids \
                        or not self.manager.sessions:
                    # the provider config doesn't support login sessions
                    raise NoMethod()

                if not storage:
                    storage = web.input()

                return self._login_get_or_post(storage)

            def _session_authz(self, sessionids, get_html=False):
                if not self.manager.sessionids \
                        or not self.manager.sessions:
                    # the provider config doesn't support sessions
                    raise NoMethod()
            
                if not self.context.session:
                    if get_html:
                        # return as no-op and let caller deal with it
                        return
                    else:
                        raise NotFound('existing session not found')

                if sessionids:
                    # format is /key,... so unpack
                    sessionids = [ urlunquote_webpy(i) for i in sessionids[1:].split(',') ]

                    for uri_key in sessionids:
                        if uri_key not in self.context.session.keys:
                            raise Forbidden('third-party session access for key "%s" forbidden' % uri_key)

            @web_method()
            def GET(self, sessionids, db=None):
                """
                Session status uses GET.

                We require sessionids from message context, and allow
                the same sessionids in the URI for RESTful
                interactions but only on the client's own current session.

                Future versions may allow third-party session
                inspection with authz.

                Optional db parameter allows delegation to this method
                from within another message handler already managing
                database transactions.

                """
                # Debug for referrer tracing
                referrer_arg = str(web.input().get('referrer'))
                referer_header = str(web.ctx.env.get('HTTP_REFERER'))
                #web.debug("in GET /session, referrer arg is '{referrer_arg}', Referrer header is '{referer_header}'".format(referrer_arg=referrer_arg, referer_header=referer_header))
                
                def db_body(db):
                    self.context = Context(self.manager, False, db)
                    self._session_authz(sessionids, get_html=True)

                if db:
                    db_body(db)
                else:
                    self._db_wrapper(db_body)

                # just report on current session status
                content_type = negotiated_content_type(
                    ['application/json'],
                    'application/json'
                    )

                def has_login_params():
                    for p in web.input():
                        if p != 'referrer' and p != 'cid':
                            return True
                    return False


                if self.manager.clients.login != None:
                    if ((self.manager.clients.login.accepts_login_get() and has_login_params())
                        or self.manager.clients.login.request_has_relevant_auth_headers()):
                        if self.context.session is None:
                            return self._login_get_or_post(web.input())
                        else:
                            # Horrible special case. The user has logged in via GET /session with arguments and then
                            # hit the back button.
                            if self.manager.preauth != None:
                                preauth_referrer = self.manager.preauth.preauth_referrer()
                                if preauth_referrer != None:
                                    web.ctx.status = '303 See Other'
                                    web.header('Location', preauth_referrer)
                                    return ''

                if self.context.session == None:
                    raise NotFound('No existing login session found.')

                # do not include sessionids since we don't want to enable
                # any XSS attack where a hidden cookie can be turned into an 
                # explicit session token by an untrusted AJAX client lib...?
                return self._login_response()

            def _login_response(self):
                now = datetime.datetime.now(timezone.utc)
                response = dict(
                    client=self.context.client,
                    attributes=list(self.context.attributes),
                    since=self.context.session.since,
                    expires=self.context.session.expires,
                    seconds_remaining=self.context.session.expires and (self.context.session.expires - now).seconds,
                    vary_headers=list(self.manager.get_http_vary()),
                    tracking=self.context.tracking,
                    )
                response = jsonWriter(response) + b'\n'
                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def PUT(self, sessionids):
                """
                Session extension uses PUT.

                We require sessionids from message context, and allow
                the same sessionids in the URI for RESTful
                interactions but only on the client's own current session.

                Future versions may allow third-party session
                extension with authz.

                """
                # just extend session and then act like GET
                now = datetime.datetime.now(timezone.utc)

                def db_body_get_context(db):
                    return Context(self.manager, False, db)

                self.context = self._db_wrapper(db_body_get_context)
                
                if self.context.session is None and self.manager.clients.login is not None and self.manager.clients.login.request_has_relevant_auth_headers():
                    return self._login_get_or_post(web.input())
                
                def db_body(db):
                    self._session_authz(sessionids)
                    self.context.session.expires = now + self.session_duration
                    self.manager.sessions.extend(self.manager, self.context, db)
                    return self._login_response()

                return self._db_wrapper(db_body)

            @web_method()
            def DELETE(self, sessionids):
                """
                Session termination uses DELETE.

                We require sessionids from message context, and allow
                the same sessionids in the URI for RESTful
                interactions but only on the client's own current session.

                Future versions may allow third-party session
                extension with authz.

                """

                preferred_final_url =  web.input().get(LOGOUT_URL)
                if preferred_final_url == None:
                    preferred_final_url = self.manager.config.get(DEFAULT_LOGOUT_PATH)

                preferred_final_url = expand_relative_url(preferred_final_url)

                if preferred_final_url == None:
                    # Should probably have a real logging facility
                    logfile=None
                    if 'env' in web.ctx:
                        logfile=web.ctx.env.get('wsgi.errors')
                    if logfile == None:
                        logfile=sys.stderr
                    print("Warning: Configuration error: no logout URL specified or configured", file=logfile)

                def db_body(db):
                    self.context = Context(self.manager, False, db)
                    self._session_authz(sessionids)
                    rv = self.manager.sessions.terminate(self.manager, self.context, db, preferred_final_url)
                    self.manager.sessionids.terminate(self.manager, self.context, db)
                    if rv == None:
                        rv = {LOGOUT_URL : preferred_final_url}
                    return rv

                response = ''

                status = "200 OK"
                try:
                    retval = self._db_wrapper(db_body)
                except NotFound as ex:
                    no_session_url = expand_relative_url(self.manager.config.get('logout_no_session_path'))
                    if no_session_url == None:
                        no_session_url = preferred_final_url
                    retval = {LOGOUT_URL : no_session_url}
                    status = "404 Not Found"

                if 'env' in web.ctx:
                    if isinstance(retval, dict):
                        response=jsonWriter(retval) + b'\n'
                        web.ctx.status = status
                        web.header('Content-Type', 'application/json')
                        web.header('Content-Length', len(response))

                return response

            def _login_get_or_post(self, storage):

                for key in self.manager.clients.login.login_keywords():
                    if key not in storage:
                        raise BadRequest('missing required parameter "%s"' % key)

                def db_body(db):
                    self.context = Context(self.manager, False, db)

                    if self.context.session or self.context.get_client_id():
                        raise Conflict('Login request conflicts with current client authentication state.')

                    self.context.session = Session()
                    # allocate new session ID first
                    self.manager.sessionids.create_unique_sessionids(self.manager, self.context)

                    try:
                        # perform authentication
                        self.context.client = self.manager.clients.login.login(self.manager, self.context, db, **storage)
                    except (KeyError, ValueError) as ev:
                        request_trace('session establishment failed: %s %s' % (type(ev), ev))
                        # we don't reveal detailed reason for failed login 
                        msg = 'session establishment with (%s) failed' \
                            % ', '.join(self.manager.clients.login.login_keywords(True))
                        raise Unauthorized(msg)

                    if self.manager.attributes.client:
                        # dig up attributes for client
                        self.manager.attributes.client.set_msg_context(self.manager, self.context, db)

                    # try to register new session
                    self.manager.sessions.new(self.manager, self.context, db)
                    return True

                # run entire sequence in a restartable db transaction
                result = self._db_wrapper(db_body)
                if result is None:
                    return
                
                # build response
                self.manager.sessionids.set_request_sessionids(self.manager, self.context)

                if self.manager.preauth != None:
                    preauth_referrer = self.manager.preauth.preauth_referrer()
                    if preauth_referrer != None:
                        web.ctx.status = '303 See Other'
                        web.header('Location', preauth_referrer)
                        return ''

                return self._login_response()

               
        class UserPassword (RestHandler):
            """
            UserPassword is a RESTful password management handler.

            Register it at a web.py URI pattern like:

               "your_passwd_prefix(/?)"
               "your_passwd_prefix(/[^/]+)"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit user ID.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            def _password_prep(self, userids):
                if not self.manager.clients.passwd:
                    # the provider config doesn't support passwords
                    raise NoMethod()

                if userids:
                    # format is /user,...
                    userids = set([ urlunquote_webpy(i) for i in userids[1:].split(',') ])
                elif self.context.get_client_id():
                    userids = [ self.context.client.get_client_id() ]
                else:
                    raise BadRequest('password management requires target userid')

                return userids

            @web_method()
            def PUT(self, userids, storage=None):
                """
                Password update uses PUT.

                Input form/query parameters:
                  password: new password to set, or missing to generate new random one
                  old_password: existing password for verification

                We require client ID from message context, and allow
                userid(s) from REST URI.  Authorized admins can manage
                other user passwords, and regular users can manage
                their own only with old_password.

                Successful response is a JSON object summarizing
                results per input userid: True or a randomly generated
                password for that user.

                On errors with multiple userids, some passwords may
                already be updated.

                """
                if not storage:
                    storage = web.input()
                password = storage.get('password', None)
                old_password = storage.get('old_password', None)

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()
                        
                    new_passwords = dict()
                    for userid in self._password_prep(userids):
                        try:
                            new_passwords[userid] = self.manager.clients.passwd.create(self.manager,
                                                                                       self.context,
                                                                                       userid,
                                                                                       password,
                                                                                       old_password,
                                                                                       db)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound('user "%s"' % userid)
                        except ValueError as ev:
                            raise Forbidden('update of password for user "%s" forbidden' % userid)
                    return new_passwords
        
                response = jsonWriter(self._db_wrapper(db_body)) + b'\n'
                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def DELETE(self, userids, storage=None):
                """
                Password disable uses DELETE.

                Input form/query parameter:
                  old_password: existing password for verification

                We require client ID from message context, and allow
                userid(s) from REST URI.  Authorized admins can manage
                other user passwords, and regular users can manage
                their own only with old_password.

                Successful response is empty.

                On errors with multiple userids, some passwords may
                already be disabled.

                """
                if not storage:
                    storage = web.input()
                old_password = storage.get('old_password', None)

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for userid in self._password_prep(userids):
                        try:
                            self.manager.clients.passwd.delete(self.manager,
                                                                 self.context,
                                                                 userid,
                                                                 old_password,
                                                                 db)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound('user "%s"' % userid)
                        except ValueError as ev:
                            raise Forbidden('delete of password for user "%s" forbidden' % userid)
    
                self._db_wrapper(db_body)
                if 'env' in web.ctx:
                    web.ctx.status = '204 No Content'
                return ''

        class UserManage (RestHandler):
            """
            UserManage is a RESTful user identity management handler.

            Register it at a web.py URI pattern like:

               "your_user_prefix(/?)"
               "your_user_prefix(/[^/]+)"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit user ID.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            @web_method()
            def GET(self, userids, storage=None):
                """
                User identity listing uses GET.

                We require client ID from message context, and allow
                userid(s) from REST URI.  Authorized clients can list
                other user identities, and regular users can always
                view their own.

                Successful response is a JSON object summarizing
                user(s).

                """
                if userids:
                    # format is /user,...
                    userids_orig = userids
                    userids = set([ urlunquote_webpy(i) for i in userids[1:].split(',') ])
                else:
                    userids = set()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    if not self.manager.clients.search:
                        if not userids \
                                or userids.difference( set([ c for c in [self.context.get_client_id()] if c ]) ):
                            raise Conflict('Server does not support listing of other client identities.')

                    if not userids:
                        # request without userids means list all users
                        clients = self.manager.clients.search.get_all_clients(self.manager, self.context)
                        response = clients and list(clients)
                    elif userids.difference( set([ c for c in [self.context.get_client_id()] if c ]) ):
                        # request with userids means list only specific users other than self
                        clients = self.manager.clients.search.get_all_clients(self.manager, self.context)
                        if clients and userids.difference( clients ):
                            web.debug(clients, userids)
                            raise NotFound('Some client identities not found: %s.' % ', '.join(userids.difference( clients )))
                        response = clients and list(clients)
                    elif len(userids) == 1 \
                         and list(userids)[0] == self.context.get_client_id():
                        # request with userid equal to self.context.client can be answered without search API
                        response = [ self.context.get_client_id() ]

                    if response == None:
                        raise ValueError()

                    return response

                try:
                    response = self._db_wrapper(db_body)
                except ValueError as ev:
                    raise Forbidden('listing of other client identities forbidden')

                response = jsonWriter(response) + b'\n'
                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def PUT(self, userids, storage=None):
                """
                User identity creation uses PUT.

                We require client ID from message context, and require
                userid(s) from REST URI.  Authorized admins can create
                user identity.
                
                Successful response is a JSON list of all
                requested clients (as relative URIs, e.g. bare client
                names).

                """
                if userids:
                    # format is /user,...
                    userids = set([ urlunquote_webpy(i) for i in userids[1:].split(',') ])
                else:
                    userids = set()

                if not self.manager.clients.manage:
                    raise NoMethod()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for userid in userids:
                        try:
                            self.manager.clients.manage.create(self.manager,
                                                               self.context,
                                                               userid,
                                                               db)
                        except ValueError as ev:
                            raise Forbidden('creation of client identity forbidden')

                    return list(userids)
        
                response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def DELETE(self, userids, storage=None):
                """
                User identity removal uses DELETE.

                We require client ID from message context, and require
                userid(s) from REST URI.  Authorized admins can delete
                user identity.
                
                """
                if userids:
                    # format is /user,...
                    userids = set([ urlunquote_webpy(i) for i in userids[1:].split(',') ])
                else:
                    userids = set()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for userid in userids:
                        try:
                            self.manager.clients.manage.delete(self.manager,
                                                               self.context,
                                                               userid,
                                                               db)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound('user "%s"' % userid)
                        except ValueError as ev:
                            raise Forbidden('delete of client identity forbidden')
    
                self._db_wrapper(db_body)
                if 'env' in web.ctx:
                    web.ctx.status = '204 No Content'
                return ''

        class AttrManage (RestHandler):
            """
            AttrManage is a RESTful attribute management handler.

            Register it at a web.py URI pattern like:

               "your_attr_prefix(/?)"
               "your_attr_prefix(/[^/]+)"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit attr ID.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            @web_method()
            def GET(self, attrs, storage=None):
                """
                Attribute listing uses GET.

                We require client ID from message context, and allow
                attrid(s) from REST URI.  Authorized clients can list
                other attributes, and regular users can always
                view their own.

                Successful response is a JSON object summarizing
                user(s).

                """
                if attrs:
                    # format is /attr,...
                    attrs = set([ urlunquote_webpy(i) for i in attrs[1:].split(',') ])
                else:
                    attrs = set()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    if not self.manager.attributes.search:
                        if not attrs \
                                or attrs.difference( self.context.attributes and self.context.attributes or set() ):
                            raise Conflict('Server does not support listing of other attributes.')

                    if not attrs:
                        # request without attrs means list all attrs
                        response = list(self.manager.attributes.search.get_all_attributes(self.manager, self.context, db, False))
                    elif self.manager.attributes.search:
                        # request with attrs means list only specific attrs
                        allattrs = set(self.manager.attributes.search.get_all_attributes(self.manager, self.context, db, False))
                        if attrs.difference( allattrs ):
                            raise NotFound('Some attributes not found: %s.' % ', '.join(attrs.difference( allattrs )))
                        response = list(attrs)
                    else:
                        # request with attrs subsetting self.context.attributes can be answered without search API
                        # we would have already raised Conflict above if it wasn't a proper subset
                        response = list(attrs)

                    return response

                try:
                    response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                except ValueError:
                    raise Forbidden('listing of other attributes forbidden')

                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def PUT(self, attrs, storage=None):
                """
                Attribute creation uses PUT.

                We require client ID from message context, and require
                attr(s) from REST URI.  Authorized admins can create
                attributes.
                
                Successful response is a JSON list of all
                requested attributes (as relative URIs, e.g. bare attribute
                names).

                """
                if attrs:
                    # format is /attr,...
                    attrs = set([ urlunquote_webpy(i) for i in attrs[1:].split(',') ])
                else:
                    attrs = set()

                if not self.manager.attributes.manage:
                    raise NoMethod()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for attr in attrs:
                        try:
                            self.manager.attributes.manage.create(self.manager,
                                                                  self.context,
                                                                  attr,
                                                                  db)
                        except ValueError as ev:
                            raise Forbidden('creation of attribute forbidden')

                    return list(attrs)
        
                response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def DELETE(self, attrs, storage=None):
                """
                Attribute removal uses DELETE.

                We require client ID from message context, and require
                attr(s) from REST URI.  Authorized admins can delete
                attributes.
                
                """
                if attrs:
                    # format is /attr,...
                    attrs = set([ urlunquote_webpy(i) for i in attrs[1:].split(',') ])
                else:
                    attrs = set()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for attr in attrs:
                        try:
                            self.manager.attributes.manage.delete(self.manager,
                                                                  self.context,
                                                                  attr,
                                                                  db)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound('attribute "%s"' % attr)
                        except ValueError as ev:
                            raise Forbidden('delete of attribute forbidden')
    
                self._db_wrapper(db_body)
                if 'env' in web.ctx:
                    web.ctx.status = '204 No Content'
                return ''

        class AttrAssign (RestHandler):
            """
            AttrAssign is a RESTful attribute assignment management handler.

            Register it at a web.py URI pattern like:

               "your_user_prefix/([^/]+)/attribute(/[^/]+)"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit user ID and one positional
            argument with a URI fragment containing an attribute list.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            @web_method()
            def GET(self, userid, attrs, storage=None):
                """
                Attribute assignment listing uses GET.

                We require client ID from message context and REST URI
                and allow attrid(s) from REST URI.  Authorized clients
                can list other users' attributes, and regular users
                can always view their own.

                Successful response is a JSON object summarizing
                user(s).

                """
                if attrs:
                    # format is /attr,...
                    attrs = set([ urlunquote_webpy(i) for i in attrs[1:].split(',') ])
                else:
                    attrs = set()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    if not self.manager.attributes.assign:
                        if userid != self.context.get_client_id():
                            raise Conflict('Server does not support listing of other user attributes.')
                        # fall back behavior only if provider API isn't available
                        allattrs = self.context.attributes
                    else:
                        allattrs = self.manager.attributes.assign.list(self.manager, self.context, userid, db)
    
                    if not attrs:
                        # request without attrs means list all of user's attrs
                        response = list(allattrs)
                    else:
                        # request with attrs means list only specific attrs
                        if attrs.difference( allattrs ):
                            raise NotFound('Some attributes not assigned: %s.' % ', '.join(attrs.difference( allattrs )))
                        response = list(attrs)

                    return response

                try:
                    response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                except ValueError:
                    raise Forbidden('listing of user attributes forbidden')

                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def PUT(self, userid, attrs, storage=None):
                """
                Attribute assignment creation uses PUT.

                We require client ID from message context, and require
                attr(s) from REST URI.  Authorized admins can create
                attributes.
                
                Successful response is a JSON list of all
                requested attributes (as relative URIs, e.g. bare attribute
                names).

                """
                if attrs:
                    # format is /attr,...
                    attrs = set([ urlunquote_webpy(i) for i in attrs[1:].split(',') ])
                else:
                    attrs = set()

                if not self.manager.attributes.assign:
                    raise NoMethod()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for attr in attrs:
                        try:
                            self.manager.attributes.assign.create(self.manager,
                                                                  self.context,
                                                                  attr,
                                                                  userid,
                                                                  db)
                        except ValueError as ev:
                            raise Forbidden('creation of attribute assignment forbidden')

                    return list(attrs)
        
                response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def DELETE(self, userid, attrs, storage=None):
                """
                Attribute removal uses DELETE.

                We require client ID from message context, and require
                attr(s) from REST URI.  Authorized admins can delete
                attributes.
                
                """
                if attrs:
                    # format is /attr,...
                    attrs = set([ urlunquote_webpy(i) for i in attrs[1:].split(',') ])
                else:
                    attrs = set()

                if not self.manager.attributes.assign:
                    raise NoMethod()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for attr in attrs:
                        try:
                            self.manager.attributes.assign.delete(self.manager,
                                                                  self.context,
                                                                  attr,
                                                                  userid,
                                                                  db)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound(str(ev))
                        except ValueError as ev:
                            raise Forbidden('delete of attribute assignment forbidden')
    
                self._db_wrapper(db_body)
                if 'env' in web.ctx:
                    web.ctx.status = '204 No Content'
                return ''

        class AttrNest (RestHandler):
            """
            AttrNest is a RESTful attribute nesting management handler.

            Register it at a web.py URI pattern like:

               "your_attr_prefix/([^/]+)/implies(/[^/]+)"

            so its methods recieve first positional argument with a
            URI fragment containing an explicit attribute ID and one
            positional argument with a URI fragment containing an
            attribute list of extra implied (parent) attributes.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            @web_method()
            def GET(self, child, parents, storage=None):
                """
                Attribute nesting listing uses GET.

                We require client ID from message context and child
                attribute from REST URI and allow parent attrid(s)
                from REST URI.  Authorized clients can list other
                attribute nesting.

                Successful response is a JSON object summarizing
                attributes.

                """
                if parents:
                    # format is /attr,...
                    parents = set([ urlunquote_webpy(i) for i in parents[1:].split(',') ])
                else:
                    parents = set()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    if not self.manager.attributes.nest:
                        raise Conflict('Server does not support listing of attribute nesting.')

                    allparents = self.manager.attributes.nest.list(self.manager, self.context, child, db)
    
                    if not parents:
                        # request without parents means list all of child's parents
                        response = list(allparents)
                    else:
                        # request with parents means list only specific parents
                        if parents.difference( allparents ):
                            raise NotFound('Some attributes not implied: %s.' % ', '.join(parents.difference( allparents )))
                        response = list(parents)

                    return response

                try:
                    response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                except KeyError:
                    raise NotFound('attribute not found')
                except ValueError:
                    raise Forbidden('listing of nested/implied attributes forbidden')

                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def PUT(self, child, parents, storage=None):
                """
                Attribute nesting creation uses PUT.

                We require client ID  from message context and child
                attribute from REST URI and allow parent attrid(s)
                from REST URI.  Authorized clients can create
                attribute nesting.
                
                Successful response is a JSON list of all
                requested attributes (as relative URIs, e.g. bare attribute
                names).

                """
                if parents:
                    # format is /attr,...
                    parents = set([ urlunquote_webpy(i) for i in parents[1:].split(',') ])
                else:
                    parents = set()

                if not self.manager.attributes.nest:
                    raise NoMethod()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for parent in parents:
                        try:
                            self.manager.attributes.nest.create(self.manager,
                                                                self.context,
                                                                parent,
                                                                child,
                                                                db)
                        except ValueError as ev:
                            raise Forbidden('creation of attribute nesting forbidden')

                    return list(parents)
        
                response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

            @web_method()
            def DELETE(self, child, parents, storage=None):
                """
                Attribute nest removal uses DELETE.

                We require client ID from message context and child
                attribute from REST URI and allow parent attrid(s)
                from REST URI.  Authorized clients can delete
                attribute nesting.
                
                """
                if parents:
                    # format is /attr,...
                    parents = set([ urlunquote_webpy(i) for i in parents[1:].split(',') ])
                else:
                    parents = set()

                if not self.manager.attributes.nest:
                    raise NoMethod()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(db=db)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for parent in parents:
                        try:
                            self.manager.attributes.nest.delete(self.manager,
                                                                self.context,
                                                                parent,
                                                                child,
                                                                db)
                        except KeyError as ev:
                            raise NotFound(str(ev))
                        except ValueError as ev:
                            raise Forbidden('delete of attribute nesting forbidden')
    
                self._db_wrapper(db_body)
                if 'env' in web.ctx:
                    web.ctx.status = '204 No Content'
                return ''

        class Preauth (RestHandler):
            """
            Preauth is a RESTful pre-authentication handler.

            Register it at a web.py URI pattern like:

               "your_preauth_prefix(/?)"
               "your_preauth_prefix(/[^/]+)"
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            @web_method()
            def GET(self, db=None):
                """
                Return pre-authentication data (e.g., display a web form for users to select among IdPs).
                """
                referrer_arg = str(web.input().get('referrer'))
                referer_header = str(web.ctx.env.get('HTTP_REFERER'))
                do_redirect = (str(web.input().get('do_redirect')) == 'true')
                #web.debug("in GET /preauth, user agent is '{user_agent}'".format(user_agent=str(web.ctx.env.get('HTTP_USER_AGENT'))))
                #web.debug("in GET /preauth, referrer arg is '{referrer_arg}', Referrer header is '{referer_header}'".format(referrer_arg=referrer_arg, referer_header=referer_header))

                def db_body(db):
                    self.context = Context(self.manager, False, db)
                    # Should probably fail or something if the user is logged in, but for now we won't bother

                if db:
                    db_body(db)
                else:
                    self._db_wrapper(db_body)

                try:
                    preauth_info = self.manager.preauth.preauth_info(self.manager, self.context, db)
                    if preauth_info == None:
                        raise NotFound()
                    if do_redirect:
                        raise web.seeother(preauth_info.get('redirect_url'))
                    response = jsonWriter(preauth_info)

                except NotImplementedError:
                    raise NotFound()

                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

        class DebugUserSession(UserSession):
            """
            This class should be used only for debugging, to provide a convenient interface for
            DELETE /session. If you decide to register it use a web.py pattern like:

               "your_session_prefix(/?)"
               "your_session_prefix(/[^/]+)"

            so its methods recieve one positional argument. Currently the only recognized argument
            is "/logout", which will do the same as DELETE /session.
            
            """
            def __init(self):
                Resthandler.__init__(self)

            @web_method()
            def GET(self, sessionids, db=None):
                return self.DELETE(sessionids)
                


        # make these classes available from factory instance
        self.RestHandler = RestHandler
        self.UserSession = UserSession
        self.UserPassword = UserPassword
        self.UserManage = UserManage
        self.AttrManage = AttrManage
        self.AttrAssign = AttrAssign
        self.AttrNest = AttrNest
        self.Preauth = Preauth
        self.DebugUserSession = DebugUserSession



class ConfigurationError(RuntimeError):
    pass
