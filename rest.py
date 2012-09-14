"""
Webauthn2 REST library supports dispatch from web.py applications.

A factory model encapsulates an entire webauthn2 security context
Manager instance that can be reused by the per-request message handler
classes expected by web.py:

  webauthn2factory = RestHandlerFactory()

  urls = (
     ...
     '/myapp/session(/[^/]+)',  webauthn2factory.UserSession,
     '/myapp/password(/[^/]+)', webauthn2factory.UserPassword
  )

These REST handlers use basic form/URI inputs and return only basic
URI or JSON results to support AJAX clients.  An application should
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


from util import *
from manager import Manager, Context
from providers import Session

import web

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

               "your_session_prefix(/[^/]+)"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit session ID prefixed with
            the '/' character.
            
            """
            def __init__(self):
                RestHandler.__init__(self)
                self.session_uri = session_uri
                self.session_duration = session_duration

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
                    raise web.NoMethod()

                if not self.manager.clients.login \
                        or not self.manager.sessionids \
                        or not self.manager.sessions:
                    # the provider config doesn't support login sessions
                    raise web.NoMethod()

                if not storage:
                    storage = web.input()
                for key in self.manager.clients.login.login_keywords():
                    if key not in storage:
                        raise BadRequest('missing required parameter "%s"' % key)

                def db_body(db):
                    self.context = Context(self.manager, False, db)

                    if self.context.session or self.context.client:
                        raise web.Conflict('login conflicts with current client authentication state')

                    self.context.session = Session()

                    # allocate new session ID first
                    self.manager.sessionids.create_unique_sessionids(self.manager, self.context)

                    try:
                        # perform authentication
                        self.context.client = self.manager.clients.login.login(self.manager, self.context, db, **storage)
                    except (KeyError, ValueError), ev:
                        # we don't reveal detailed reason for failed login
                        raise web.Forbidden('session establishment for given parameters (%s)'
                                            % ', '.join(self.manager.clients.login.login_keywords(True)))

                    if self.manager.attributes.client:
                        # dig up attributes for client
                        self.manager.attributes.client.set_msg_context(self.manager, self.context)

                    # try to register new session
                    self.manager.sessions.new(self.manager, self.context, db)

                # run entire sequence in a restartable db transaction
                self._db_wrapper(db_body)
                
                # build response
                self.manager.sessionids.set_request_sessionids(self.manager, self.context)
                uri = self.session_uri
                keys = ','.join([ urlquote(i) for i in self.context.session.keys ]) + '\n'
                if uri:
                    uri += '/' + keys
                else:
                    uri = keys

                if 'env' in web.ctx:
                    web.ctx.status = '201 Created'
                    web.header('Content-Type', 'text/uri-list')
                    web.header('Content-Length', len(uri))
                return uri

            def _session_authz(self, sessionids):
                if not self.manager.sessionids \
                        or not self.manager.sessions:
                    # the provider config doesn't support sessions
                    raise web.NoMethod()

                if not self.context.session:
                    raise web.Forbidden('unauthenticated session access')

                if sessionids:
                    # format is /key,... so unpack
                    sessionids = [ urlunquote(i) for i in sessionids[1:].split(',') ]

                    for uri_key in sessionids:
                        if uri_key not in self.context.session.keys:
                            raise web.Forbidden('third-party session access for key "%s"' % uri_key)
                        
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
                def db_body(db):
                    self.context = Context(self.manager, False, db)
                    self._session_authz(sessionids)

                if db:
                    db_body(db)
                else:
                    self._db_wrapper(db_body)

                # just report on current session status
                now = datetime.datetime.now(pytz.timezone('UTC'))
                response = dict(
                    client=self.context.client,
                    attributes=list(self.context.attributes),
                    since=self.context.session.since,
                    expires=self.context.session.expires,
                    seconds_remaining=self.context.session.expires and (self.context.session.expires - now).seconds
                    )
                response = jsonWriter(response)
                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

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
                now = datetime.datetime.now(pytz.timezone('UTC'))

                def db_body(db):
                    self.context = Context(self.manager, False, db)
                    self._session_authz(sessionids)
                    self.context.session.expires = now + self.session_duration
                    self.manager.sessions.extend(self.manager, self.context, db)
                    return self.GET(sessionids, db)

                return self._db_wrapper(db_body)

            def DELETE(self, sessionids):
                """
                Session termination uses DELETE.

                We require sessionids from message context, and allow
                the same sessionids in the URI for RESTful
                interactions but only on the client's own current session.

                Future versions may allow third-party session
                extension with authz.

                """
                def db_body(db):
                    self.context = Context(self.manager, False, db)
                    self._session_authz(sessionids)
                    self.manager.sessions.terminate(self.manager, self.context, db)

                self._db_wrapper(db_body)
                if 'env' in web.ctx:
                    web.ctx.status = '204 No Content'
                return ''
               
        class UserPassword (RestHandler):
            """
            UserPassword is a RESTful password management handler.

            Register it at a web.py URI pattern like:

               "your_passwd_prefix(/[^/]+)"

            so its methods recieve one positional argument with a URI
            fragment containing an explicit user ID.
            
            """
            def __init__(self):
                RestHandler.__init__(self)

            def _password_prep(self, userids):
                if not self.manager.clients.passwd:
                    # the provider config doesn't support passwords
                    raise web.NoMethod()

                if userids:
                    # format is /user,...
                    userids = set([ urlunquote(i) for i in userids[1:].split(',') ])
                elif self.context.client:
                    userids = [ self.context.client ]
                else:
                    raise BadRequest('password management requires target userid')

                return userids

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
                    self.context = Context(self.manager, False, db)
                    userids = self._password_prep(userids)
                    new_passwords = dict()
                    for userid in userids:
                        try:
                            new_passwords[userid] = self.manager.clients.password.create(self.manager,
                                                                                         self.context,
                                                                                         userid,
                                                                                         password,
                                                                                         old_passwd)
                        except KeyError, ev:
                            # this is only raised by password provider if authorized
                            raise web.NotFound('user "%s"' % uri_key)
                        except ValueError, ev:
                            raise web.Forbidden('update of password for user "%s"' % uri_key)
                    return new_passwords
        
                response = jsonWriter(self._db_wrapper(db_body))
                if 'env' in web.ctx:
                    web.ctx.status = '200 OK'
                    web.header('Content-Type', 'application/json')
                    web.header('Content-Length', len(response))
                return response

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
                    self.context = Context(self.manager, False, db)
                    userids = self._password_prep(userids)

                    for userid in userids:
                        try:
                            self.manager.clients.password.delete(self.manager,
                                                                 self.context,
                                                                 userid,
                                                                 old_passwd)
                        except KeyError, ev:
                            # this is only raised by password provider if authorized
                            raise web.NotFound('user "%s"' % uri_key)
                        except ValueError, ev:
                            raise web.Forbidden('delete of password for user "%s"' % uri_key)
    
                self._db_wrapper(db_body)
                if 'env' in web.ctx:
                    web.ctx.status = '204 No Content'
                return ''


        # make these classes available from factory instance
        self.RestHandler = RestHandler
        self.UserSession = UserSession
        self.UserPassword = UserPassword

