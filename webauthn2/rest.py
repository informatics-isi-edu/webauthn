# 
# Copyright 2012-2023 University of Southern California
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
         def db_body(conn, cur):
            self.context = self.manager.get_request_context(conn=conn, cur=cur)
            ... # other application use of conn, cur
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

app = flask.Flask(__name__)

# instantiate manager based on service config
_manager = Manager()

def get_log_parts(start_time_key, request_guid_key, content_range_key, content_type_key):
    """Generate a dictionary of interpolation keys used by our logging template.

       Arguments:
          start_time_key: key to entry in deriva_ctx w/ current request start timestamp
          request_guid_key: key to entry in deriva_ctx w/ current request GUID
          content_range_key: key to entry in deriva_ctx w/ HTTP range
          content_type_key: key to entry in deriva_ctx w/ HTTP content type
    """
    now = datetime.datetime.now(timezone.utc)
    elapsed = (now - getattr(deriva_ctx, start_time_key))
    client_identity_obj = deriva_ctx.webauthn2_context.client if deriva_ctx.webauthn2_context else None
    parts = dict(
        elapsed = elapsed.seconds + 0.001 * (elapsed.microseconds/1000),
        client_ip = flask.request.remote_addr,
        client_identity_obj = client_identity_obj,
        reqid = getattr(deriva_ctx, request_guid_key),
        content_range = getattr(deriva_ctx, content_range_key),
        content_type = getattr(deriva_ctx, content_type_key),
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
    if dcctx is None:
        return None
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
        dcctx = flask.request.environ.get('HTTP_DERIVA_CLIENT_CONTEXT', 'null')
        dcctx = urllib.parse.unquote(dcctx)
        dcctx = prune_excessive_dcctx(json.loads(dcctx))
    except Exception as e:
        deriva_debug('Error during dcctx decoding: %s' % e)
        dcctx = None

    od = OrderedDict([
        (k, v) for k, v in [
            ('elapsed', parts['elapsed']),
            ('req', parts['reqid']),
            ('scheme', flask.request.scheme),
            ('host', flask.request.host),
            ('status', deriva_ctx.deriva_response.status),
            ('method', flask.request.method),
            ('path', flask.request.environ['REQUEST_URI']),
            ('range', parts['content_range']),
            ('type', parts['content_type']),
            ('client', parts['client_ip']),
            ('user', parts['client_identity_obj']),
            ('referrer', flask.request.environ.get('HTTP_REFERER')),
            ('agent', flask.request.environ.get('HTTP_USER_AGENT')),
            ('track', deriva_ctx.webauthn2_context.tracking),
            ('dcctx', dcctx),
        ]
        if v
    ])
    if len(od.get('referrer', '')) > 1000:
        # truncate overly long URL
        od['referrer_md5'] = hashlib.md5(od['referrer'].encode()).hexdigest()
        od['referrer'] = od['referrer'][0:500]

    if deriva_ctx.webauthn2_context and deriva_ctx.webauthn2_context.session:
        session = deriva_ctx.webauthn2_context.session
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

@app.before_request
def before_request():
    # request context init
    deriva_ctx.webauthn_dispatched_handler = None
    deriva_ctx.deriva_response = flask.Response() # allow us to accumulate response content by side-effect
    deriva_ctx.webauthn_request_guid = base64.b64encode( struct.pack('Q', random.getrandbits(64)) ).decode()
    deriva_ctx.webauthn_start_time = datetime.datetime.now(timezone.utc)
    deriva_ctx.webauthn_request_content_range = None
    deriva_ctx.webauthn_content_type = None
    deriva_ctx.webauthn2_context = Context() # set empty context for sanity
    deriva_ctx.webauthn_request_trace = request_trace

@app.after_request
def after_request(response):
    if isinstance(response, flask.Response):
        deriva_ctx.webauthn_status = response.status
    elif isinstance(response, RestException):
        deriva_ctx.webauthn_status = response.code
    deriva_ctx.webauthn_content_type = response.headers.get('content-type', 'none')
    if 'content-range' in response.headers:
        content_range = response.headers['content-range']
        if content_range.startswith('bytes '):
            content_range = content_range[6:]
        deriva_ctx.webauthn_request_content_range = content_range
    elif 'content-length' in response.headers:
        deriva_ctx.webauthn_request_content_range = '*/%s' % response.headers['content-length']
    else:
        deriva_ctx.webauthn_request_content_range = '*/0'

    if deriva_ctx.webauthn_dispatched_handler is not None \
       and hasattr(deriva_ctx.webauthn_dispatched_handler, 'context'):
        deriva_ctx.webauthn2_context = deriva_ctx.webauthn_dispatched_handler.context 

    logger.info( request_final_json(log_parts()) )
    return response

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

        class RestHandler (DatabaseConnection, flask.views.MethodView):
            """
            RestHandler is a base class suitable for use as a flask request handler.

            It initializes its self.manager and its parent class
            DatabaseConnection.  Derived application classes must
            implement their own web methods PUT, GET, etc. and
            initialize their own self.context such as:

               self.context = self.manager.get_request_context(conn=conn, cur=cur)

            if they already have opened a pooled connection, or:

               self.context = self.manager.get_request_context()

            if the handler is not already connecte to the database.

            """
            def __init__(self):
                DatabaseConnection.__init__(self, manager.config)
                self.manager = manager
                deriva_ctx.webauthn_dispatched_handler = self

        class UserSession (RestHandler):
            """
            UserSession is a RESTful login/logout handler.

            Register it at a flask route like:

               "your_session_prefix"
               "your_session_prefix/"
               "your_session_prefix/<sessionids>"
               "your_session_prefix/<sessionids>/"

            so its methods recieve one optional argument with a URI
            fragment containing an explicit session ID
            
            """
            def __init__(self):
                RestHandler.__init__(self)
                self.session_uri = session_uri
                self.session_duration = session_duration

            def post(self, sessionids='', storage=None):
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
                    # no POST support for session ID URLs
                    raise NoMethod()

                if not self.manager.clients.login \
                        or not self.manager.sessionids \
                        or not self.manager.sessions:
                    # the provider config doesn't support login sessions
                    raise NoMethod()

                if not storage:
                    storage = web_input()

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
                    sessionids = [ urlunquote(i) for i in sessionids.split(',') ]

                    for uri_key in sessionids:
                        if uri_key not in self.context.session.keys:
                            raise Forbidden('third-party session access for key "%s" forbidden' % uri_key)

            def get(self, sessionids='', conn=None, cur=None):
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
                referrer_arg = str(web_input().get('referrer'))
                referer_header = str(flask.request.environ.get('HTTP_REFERER'))
                deriva_debug("in GET /session, referrer arg is '{referrer_arg}', Referrer header is '{referer_header}'".format(referrer_arg=referrer_arg, referer_header=referer_header))
                
                def db_body(conn, cur):
                    self.context = Context(self.manager, False, conn, cur)
                    self._session_authz(sessionids, get_html=True)

                if conn is not None and cur is not None:
                    db_body(conn, cur)
                else:
                    self._db_wrapper(db_body)

                # just report on current session status
                content_type = negotiated_content_type(
                    flask.request.environ,
                    ['application/json'],
                    'application/json'
                    )

                def has_login_params():
                    for p in web_input():
                        if p != 'referrer' and p != 'cid':
                            return True
                    return False


                if self.manager.clients.login != None:
                    if ((self.manager.clients.login.accepts_login_get() and has_login_params())
                        or self.manager.clients.login.request_has_relevant_auth_headers()):
                        if self.context.session is None:
                            return self._login_get_or_post(web_input())
                        else:
                            # Horrible special case. The user has logged in via GET /session with arguments and then
                            # hit the back button.
                            if self.manager.preauth != None:
                                preauth_referrer = self.manager.preauth.preauth_referrer()
                                if preauth_referrer != None:
                                    deriva_ctx.deriva_response.set_data('')
                                    deriva_ctx.deriva_response.status = '303 See Other'
                                    deriva_ctx.deriva_response.location = preauth_referrer
                                    return deriva_ctx.deriva_response

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
                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def put(self, sessionids=''):
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

                def db_body_get_context(conn, cur):
                    return Context(self.manager, False, conn, cur)

                self.context = self._db_wrapper(db_body_get_context)
                
                if self.context.session is None and self.manager.clients.login is not None and self.manager.clients.login.request_has_relevant_auth_headers():
                    return self._login_get_or_post(web_input())
                
                def db_body(conn, cur):
                    self._session_authz(sessionids)
                    self.context.session.expires = now + self.session_duration
                    self.manager.sessions.extend(self.manager, self.context, conn, cur)
                    return self._login_response()

                return self._db_wrapper(db_body)

            def delete(self, sessionids=''):
                """
                Session termination uses DELETE.

                We require sessionids from message context, and allow
                the same sessionids in the URI for RESTful
                interactions but only on the client's own current session.

                Future versions may allow third-party session
                extension with authz.

                """

                preferred_final_url =  web_input().get(LOGOUT_URL)
                if preferred_final_url == None:
                    preferred_final_url = self.manager.config.get(DEFAULT_LOGOUT_PATH)

                preferred_final_url = expand_relative_url(preferred_final_url)

                if preferred_final_url == None:
                    deriva_debug("Warning: Configuration error: no logout URL specified or configured")

                def db_body(conn, cur):
                    self.context = Context(self.manager, False, conn, cur)
                    self._session_authz(sessionids)
                    rv = self.manager.sessions.terminate(self.manager, self.context, conn, cur, preferred_final_url)
                    self.manager.sessionids.terminate(self.manager, self.context, conn, cur)
                    if rv == None:
                        rv = {LOGOUT_URL : preferred_final_url}
                    return rv

                try:
                    retval = self._db_wrapper(db_body)
                    status = "200 OK"
                except NotFound as ex:
                    no_session_url = expand_relative_url(self.manager.config.get('logout_no_session_path'))
                    if no_session_url is None:
                        no_session_url = preferred_final_url
                    retval = {LOGOUT_URL : no_session_url}
                    status = "404 Not Found"

                response=jsonWriter(retval) + b'\n'
                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = status
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def _login_get_or_post(self, storage):

                for key in self.manager.clients.login.login_keywords():
                    if key not in storage:
                        raise BadRequest('missing required parameter "%s"' % key)

                def db_body(conn, cur):
                    self.context = Context(self.manager, False, conn, cur)

                    if self.context.session or self.context.get_client_id():
                        raise Conflict('Login request conflicts with current client authentication state.')

                    self.context.session = Session()
                    # allocate new session ID first
                    self.manager.sessionids.create_unique_sessionids(self.manager, self.context)

                    try:
                        # perform authentication
                        self.context.client = self.manager.clients.login.login(self.manager, self.context, conn, cur, **storage)
                    except (KeyError, ValueError) as ev:
                        request_trace('session establishment failed: %s %s' % (type(ev), ev))
                        # we don't reveal detailed reason for failed login 
                        raise Unauthorized('Session establishment failed.')

                    if self.manager.attributes.client:
                        # dig up attributes for client
                        self.manager.attributes.client.set_msg_context(self.manager, self.context, conn, cur)

                    # try to register new session
                    self.manager.sessions.new(self.manager, self.context, conn, cur)

                # run entire sequence in a restartable db transaction
                self._db_wrapper(db_body)

                # build response
                self.manager.sessionids.set_request_sessionids(self.manager, self.context)

                if self.manager.preauth is not None:
                    preauth_referrer = self.manager.preauth.preauth_referrer()
                    if preauth_referrer is not None:
                        deriva_ctx.deriva_response.status = '303 See Other'
                        deriva_ctx.deriva_response.location = preauth_referrer
                        deriva_ctx.deriva_respones.set_data('')
                        return deriva_ctx.deriva_response

                return self._login_response()

               
        class UserPassword (RestHandler):
            """
            UserPassword is a RESTful password management handler.

            Register it at a flask URI pattern like:

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
                    # format is user,...
                    userids = set([ urlunquote(i) for i in userids.split(',') ])
                elif self.context.get_client_id():
                    userids = [ self.context.client.get_client_id() ]
                else:
                    raise BadRequest('password management requires target userid')

                return userids

            def put(self, userids='', storage=None):
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
                    storage = web_input()
                password = storage.get('password', None)
                old_password = storage.get('old_password', None)

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
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
                                                                                       conn,
                                                                                       cur)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound('user "%s"' % userid)
                        except ValueError as ev:
                            raise Forbidden('update of password for user "%s" forbidden' % userid)
                    return new_passwords
        
                response = jsonWriter(self._db_wrapper(db_body)) + b'\n'
                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def delete(self, userids='', storage=None):
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
                    storage = web_input()
                old_password = storage.get('old_password', None)

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for userid in self._password_prep(userids):
                        try:
                            self.manager.clients.passwd.delete(self.manager,
                                                               self.context,
                                                               userid,
                                                               old_password,
                                                               conn,
                                                               cur)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound('user "%s"' % userid)
                        except ValueError as ev:
                            raise Forbidden('delete of password for user "%s" forbidden' % userid)
    
                self._db_wrapper(db_body)
                deriva_ctx.deriva_response.set_data('')
                deriva_ctx.deriva_response.status = '204 No Content'
                return deriva_ctx.deriva_response

        class UserManage (RestHandler):
            """
            UserManage is a RESTful user identity management handler.

            Register it at a flask route like:

               "your_user_prefix"
               "your_user_prefix/"
               "your_user_prefix/<userids>"
               "your_user_prefix/<userids>/"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit user ID.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            def get(self, userids='', storage=None):
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
                    # format is user,...
                    userids_orig = userids
                    userids = set([ urlunquote(i) for i in userids.split(',') ])
                else:
                    userids = set()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
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
                            deriva_debug(clients, userids)
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
                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def put(self, userids='', storage=None):
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
                    # format is user,...
                    userids = set([ urlunquote(i) for i in userids.split(',') ])
                else:
                    userids = set()

                if not self.manager.clients.manage:
                    raise NoMethod()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for userid in userids:
                        try:
                            self.manager.clients.manage.create(self.manager,
                                                               self.context,
                                                               userid,
                                                               conn,
                                                               cur)
                        except ValueError as ev:
                            raise Forbidden('creation of client identity forbidden')

                    return list(userids)
        
                response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def delete(self, userids='', storage=None):
                """
                User identity removal uses DELETE.

                We require client ID from message context, and require
                userid(s) from REST URI.  Authorized admins can delete
                user identity.
                
                """
                if userids:
                    # format is user,...
                    userids = set([ urlunquote(i) for i in userids.split(',') ])
                else:
                    userids = set()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for userid in userids:
                        try:
                            self.manager.clients.manage.delete(self.manager,
                                                               self.context,
                                                               userid,
                                                               conn,
                                                               cur)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound('user "%s"' % userid)
                        except ValueError as ev:
                            raise Forbidden('delete of client identity forbidden')
    
                self._db_wrapper(db_body)
                deriva_ctx.deriva_response.set_data('')
                deriva_ctx.deriva_response.status = '204 No Content'
                return deriva_ctx.deriva_response

        class AttrManage (RestHandler):
            """
            AttrManage is a RESTful attribute management handler.

            Register it at a flask route like:

               "your_attr_prefix"
               "your_attr_prefix/"
               "your_attr_prefix/<attrs>"
               "your_attr_prefix/<attrs>/"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit attr ID.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            def get(self, attrs='', storage=None):
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
                    # format is attr,...
                    attrs = set([ urlunquote(i) for i in attrs.split(',') ])
                else:
                    attrs = set()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    if not self.manager.attributes.search:
                        if not attrs \
                                or attrs.difference( self.context.attributes and self.context.attributes or set() ):
                            raise Conflict('Server does not support listing of other attributes.')

                    if not attrs:
                        # request without attrs means list all attrs
                        response = list(self.manager.attributes.search.get_all_attributes(self.manager, self.context, conn, cur, False))
                    elif self.manager.attributes.search:
                        # request with attrs means list only specific attrs
                        allattrs = set(self.manager.attributes.search.get_all_attributes(self.manager, self.context, conn, cur, False))
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

                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def put(self, attrs='', storage=None):
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
                    # format is attr,...
                    attrs = set([ urlunquote(i) for i in attrs.split(',') ])
                else:
                    attrs = set()

                if not self.manager.attributes.manage:
                    raise NoMethod()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for attr in attrs:
                        try:
                            self.manager.attributes.manage.create(self.manager,
                                                                  self.context,
                                                                  attr,
                                                                  conn,
                                                                  cur)
                        except ValueError as ev:
                            raise Forbidden('creation of attribute forbidden')

                    return list(attrs)
        
                response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def delete(self, attrs='', storage=None):
                """
                Attribute removal uses DELETE.

                We require client ID from message context, and require
                attr(s) from REST URI.  Authorized admins can delete
                attributes.
                
                """
                if attrs:
                    # format is attr,...
                    attrs = set([ urlunquote(i) for i in attrs.split(',') ])
                else:
                    attrs = set()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for attr in attrs:
                        try:
                            self.manager.attributes.manage.delete(self.manager,
                                                                  self.context,
                                                                  attr,
                                                                  conn,
                                                                  cur)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound('attribute "%s"' % attr)
                        except ValueError as ev:
                            raise Forbidden('delete of attribute forbidden')
    
                self._db_wrapper(db_body)
                deriva_ctx.deriva_response.set_data('')
                deriva_ctx.deriva_response.status = '204 No Content'
                return deriva_ctx.deriva_response

        class AttrAssign (RestHandler):
            """
            AttrAssign is a RESTful attribute assignment management handler.

            Register it at a flask route like:

               "your_user_prefix/<userid>/attribute"
               "your_user_prefix/<userid>/attribute/"
               "your_user_prefix/<userid>/attribute/<attrs>"
               "your_user_prefix/<userid>/attribute/<attrs>/"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit user ID and one positional
            argument with a URI fragment containing an attribute list.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            def get(self, userid, attrs='', storage=None):
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
                    # format is attr,...
                    attrs = set([ urlunquote(i) for i in attrs.split(',') ])
                else:
                    attrs = set()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    if not self.manager.attributes.assign:
                        if userid != self.context.get_client_id():
                            raise Conflict('Server does not support listing of other user attributes.')
                        # fall back behavior only if provider API isn't available
                        allattrs = self.context.attributes
                    else:
                        allattrs = self.manager.attributes.assign.list(self.manager, self.context, userid, conn, cur)
    
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

                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def put(self, userid, attrs='', storage=None):
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
                    # format is attr,...
                    attrs = set([ urlunquote(i) for i in attrs.split(',') ])
                else:
                    attrs = set()

                if not self.manager.attributes.assign:
                    raise NoMethod()

                def db_body(db):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for attr in attrs:
                        try:
                            self.manager.attributes.assign.create(self.manager,
                                                                  self.context,
                                                                  attr,
                                                                  userid,
                                                                  conn,
                                                                  cur)
                        except ValueError as ev:
                            raise Forbidden('creation of attribute assignment forbidden')

                    return list(attrs)
        
                response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def delete(self, userid, attrs='', storage=None):
                """
                Attribute removal uses DELETE.

                We require client ID from message context, and require
                attr(s) from REST URI.  Authorized admins can delete
                attributes.
                
                """
                if attrs:
                    # format is attr,...
                    attrs = set([ urlunquote(i) for i in attrs.split(',') ])
                else:
                    attrs = set()

                if not self.manager.attributes.assign:
                    raise NoMethod()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for attr in attrs:
                        try:
                            self.manager.attributes.assign.delete(self.manager,
                                                                  self.context,
                                                                  attr,
                                                                  userid,
                                                                  conn,
                                                                  cur)
                        except KeyError as ev:
                            # this is only raised by password provider if authorized
                            raise NotFound(str(ev))
                        except ValueError as ev:
                            raise Forbidden('delete of attribute assignment forbidden')
    
                self._db_wrapper(db_body)
                deriva_ctx.deriva_response.set_data('')
                deriva_ctx.deriva_response.status = '204 No Content'
                return deriva_ctx.deriva_response

        class AttrNest (RestHandler):
            """
            AttrNest is a RESTful attribute nesting management handler.

            Register it at a flask route like:

               "your_attr_prefix/<child>/implies"
               "your_attr_prefix/<child>/implies/"
               "your_attr_prefix/<child>/implies/<parents>"
               "your_attr_prefix/<child>/implies/<parents>/"

            so its methods recieve first positional argument with a
            URI fragment containing an explicit attribute ID and one
            positional argument with a URI fragment containing an
            attribute list of extra implied (parent) attributes.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            def get(self, child, parents, storage=None):
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
                    # format is attr,...
                    parents = set([ urlunquote(i) for i in parents.split(',') ])
                else:
                    parents = set()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    if not self.manager.attributes.nest:
                        raise Conflict('Server does not support listing of attribute nesting.')

                    allparents = self.manager.attributes.nest.list(self.manager, self.context, child, conn, cur)
    
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

                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def put(self, child, parents, storage=None):
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
                    # format is attr,...
                    parents = set([ urlunquote(i) for i in parents.split(',') ])
                else:
                    parents = set()

                if not self.manager.attributes.nest:
                    raise NoMethod()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for parent in parents:
                        try:
                            self.manager.attributes.nest.create(self.manager,
                                                                self.context,
                                                                parent,
                                                                child,
                                                                conn,
                                                                cur)
                        except ValueError as ev:
                            raise Forbidden('creation of attribute nesting forbidden')

                    return list(parents)
        
                response = jsonWriter( self._db_wrapper(db_body) ) + b'\n'
                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

            def delete(self, child, parents, storage=None):
                """
                Attribute nest removal uses DELETE.

                We require client ID from message context and child
                attribute from REST URI and allow parent attrid(s)
                from REST URI.  Authorized clients can delete
                attribute nesting.
                
                """
                if parents:
                    # format is attr,...
                    parents = set([ urlunquote(i) for i in parents.split(',') ])
                else:
                    parents = set()

                if not self.manager.attributes.nest:
                    raise NoMethod()

                def db_body(conn, cur):
                    try:
                        self.context = self.manager.get_request_context(conn=conn, cur=cur)
                    except (ValueError, IndexError):
                        raise Unauthorized()

                    for parent in parents:
                        try:
                            self.manager.attributes.nest.delete(self.manager,
                                                                self.context,
                                                                parent,
                                                                child,
                                                                conn,
                                                                cur)
                        except KeyError as ev:
                            raise NotFound(str(ev))
                        except ValueError as ev:
                            raise Forbidden('delete of attribute nesting forbidden')
    
                self._db_wrapper(db_body)
                deriva_ctx.deriva_response.set_data('')
                deriva_ctx.deriva_response.status = '204 No Content'
                return deriva_ctx.deriva_response

        class Preauth (RestHandler):
            """
            Preauth is a RESTful pre-authentication handler.

            Register it at a flask route like:

               "your_preauth_prefix"
               "your_preauth_prefix/"
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            def get(self, conn=None, cur=None):
                """
                Return pre-authentication data (e.g., display a web form for users to select among IdPs).
                """
                referrer_arg = str(web_input().get('referrer'))
                referer_header = str(flask.request.environ.get('HTTP_REFERER'))
                do_redirect = (str(web_input().get('do_redirect')) == 'true')
                #deriva_debug("in GET /preauth, user agent is '{user_agent}'".format(user_agent=str(flask.request.environ.get('HTTP_USER_AGENT'))))
                #deriva_debug("in GET /preauth, referrer arg is '{referrer_arg}', Referrer header is '{referer_header}'".format(referrer_arg=referrer_arg, referer_header=referer_header))

                def db_body(conn, cur):
                    self.context = Context(self.manager, False, conn, cur)
                    # Should probably fail or something if the user is logged in, but for now we won't bother

                if conn is not None and cur is not None:
                    db_body(conn, cur)
                else:
                    self._db_wrapper(db_body)

                try:
                    preauth_info = self.manager.preauth.preauth_info(self.manager, self.context, conn, cur)
                    if preauth_info == None:
                        raise NotFound()
                    if do_redirect:
                        raise web.seeother(preauth_info.get('redirect_url'))
                    response = jsonWriter(preauth_info)

                except NotImplementedError:
                    raise NotFound()

                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

        class DebugUserSession(UserSession):
            """
            This class should be used only for debugging, to provide a convenient interface for
            DELETE /session. If you decide to register it use a flask route like:

               "your_session_prefix"
               "your_session_prefix/"
               "your_session_prefix/<sessionids>"
               "your_session_prefix/<sessionids>/"

            so its methods recieve one positional argument. Currently the only recognized argument
            is "/logout", which will do the same as DELETE /session.
            
            """
            def __init(self):
                RestHandler.__init__(self)

            def get(self, sessionids='', conn=None, cur=None):
                return self.delete(sessionids)
                
        class Discovery(RestHandler):
            """
            This class is used to provide discovery information (e.g., oauth2 sessions accepted in request headers).

            Register it at a flask route like:

               "your_session_prefix"
               "your_session_prefix/"
            
            """
            def __init(self):
                RestHandler.__init__(self)

            def get(self, conn=None, cur=None):
                response = jsonWriter(self.manager.discovery_info) + b'\n'
                deriva_ctx.deriva_response.set_data(response)
                deriva_ctx.deriva_response.status = '200 OK'
                deriva_ctx.deriva_response.content_type = 'application/json'
                deriva_ctx.deriva_response.content_length = len(response)
                return deriva_ctx.deriva_response

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
        self.Discovery = Discovery


class ConfigurationError(RuntimeError):
    pass

# instantiate REST endpoints and setup flask routes...
_handler_factory = RestHandlerFactory(manager=_manager)

_Session_view = app.route(
    '/session'
)(app.route(
    '/session/'
)(app.route(
    '/session/<sessionids>'
)(app.route(
    '/session/<sessionids>/'
)(_handler_factory.UserSession.as_view('Session')))))

_Preauth_view = app.route(
    '/preauth'
)(app.route(
    '/preauth/'
)(_handler_factory.Preauth.as_view('Preauth')))

_Discovery_view = app.route(
    '/discovery'
)(app.route(
    '/discovery/'
)(_handler_factory.Discovery.as_view('Discovery')))

# TODO: delete entirely?
# roughed these out for flask port, but don't think they are
# useful in contemporary deployments...
_disabled_api_routes = """

if _manager.clients.passwd is not None:
    # only route when password endpoint is configured
    _Password_view = app.route(
        '/password'
    )(app.route(
        '/password/<userids>'
    )(_handler_factory.UserPassword.as_view('Password')))

if _manager.clients.search is not None \
   and _manager.clients.manage is not None:
    # only route when user management endpoints are configured
    _User_view = app.route(
        '/user'
    )(app.route(
        '/user/<userids>'
    )(_handler_factory.UserManage.as_view('User')))

if _manager.attributes.search is not None \
   and _manager.attributes.manage is not None:
    # only route when attribute management endpoints are configured
    _Attribute_view = app.route(
        '/attribute'
    )(app.route(
        '/attribute/<attrs>'
    )(_handler_factory.AttrManage.as_view('Attribute')))

if _manager.attributes.assign is not None:
    # only route when attribute assignment endpoint is configured
    _AttributeAssign_view = app.route(
        '/user/<userid>/attribute'
    )(app.route(
        '/user/<userid>/attribute/<attrs>'
    )(_handler_factory.AttrAssign.as_view('AttributeAssign')))

if _manager.attributes.nest is not None:
    # only route when attribute nesting endpoint is configured
    _AttributeNest_view = app.route(
        '/attribute/<child>/implies'
    )(app.route(
        '/user/<child>/implies/<parents>'
    )(_handler_factory.AttrNest.as_view('AttributeNest')))

"""
