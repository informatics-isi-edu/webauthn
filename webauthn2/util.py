
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

import psycopg2
import psycopg2.extensions
import psycopg2.extras
import web
import urllib
import urllib.error
import datetime
import math
import random
import time
import os
import sys
import traceback
import base64

psycopg2.extensions.register_type(psycopg2.extensions.JSON)
psycopg2.extensions.register_type(psycopg2.extensions.JSONARRAY)
psycopg2.extensions.register_type(psycopg2.extensions.JSONB)
psycopg2.extensions.register_type(psycopg2.extensions.JSONBARRAY)

import json

jsonReader = json.loads
jsonFileReader = json.load

LOGOUT_URL = "logout_url"
DEFAULT_LOGOUT_PATH = "default_logout_path"

def deriva_debug(*args):
    """Shim to emulate web.debug non-logger diagnostics.
    """
    if len(args) > 1:
        v = str(tuple(args))
    else:
        v = str(args[0])

    print(v, file=sys.stderr, flush=True)

class web_storage(dict):
    """Shim to emulate web.storage attr-dict class.
    """
    def __getattribute__(self, a):
        """Allow reading of dict keys as attributes.

        Don't allow dict keys to shadow actual attributes of dict, and
        proxy those instead.
        """
        sself = super(web_storage, self)
        try:
            return sself.__getattribute__(a)
        except:
            if a in self:
                return self[a]
            else:
                raise AttributeError(a)

def web_input():
    """Shim to emulate web.input form/query parser.

    This returns form inputs if available or falls back to query params.
    """
    storage1 = web_storage(flask.request.form)
    storage2 = web_storage(flask.request.args)
    #deriva_debug('web_input %r environ=%r form=%r args=%r' % (flask.request.full_path, flask.request.environ, storage1, storage2))
    if storage1:
        return storage1
    else:
        return storage2

def jsonWriter(o, indent=None):
    def munge(o):
        if isinstance(o, (dict, web_storage)):
            return {
                p[0]: munge(p[1])
                for p in o.items()
            }
        elif isinstance(o, str):
            return o
        elif isinstance(o, (datetime.datetime, datetime.date)):
            return str(o)
        elif hasattr(o, '__iter__'):
            return [ munge(e) for e in o ]
        else:
            return o

    return json.dumps( munge(o), indent=indent, ensure_ascii=False ).encode()

def negotiated_content_type(environ, supported_types=['text/csv', 'application/json', 'application/x-json-stream'], default=None):
    """Determine negotiated response content-type from Accept header.

       environ: the WSGI dict-like environment containing
         HTTP_* header content.

       supported_types: a list of MIME types the caller would be able
         to implement if the client has requested one.

       default: a MIME type or None to return if none of the
         supported_types were requested by the client.

       This function considers the preference qfactors encoded in the
       client request to choose the preferred type when there is more
       than one supported type that the client would accept.

    """
    def accept_pair(s):
        """parse one Accept header pair into (qfactor, type)."""
        parts = s.split(';')
        q = 1.0
        t = parts[0].strip()
        for p in parts[1:]:
            fields = p.split('=')
            if len(fields) == 2 and fields[0] == 'q':
                q = float(fields[1])
        return (q, t)

    try:
        accept = environ['HTTP_ACCEPT']
    except:
        accept = ""
            
    accept_types = [ 
        pair[1]
        for pair in sorted(
            [ accept_pair(s) for s in accept.lower().split(',') ],
            key=lambda pair: pair[0]
            ) 
        ]

    if accept_types:
        for accept_type in accept_types:
            if accept_type in supported_types:
                return accept_type

    return default

def merge_config(overrides=None, defaults=None, jsonFileName=None, built_ins={}):
    """
    Construct web_storage config result from inputs.

    The configuration parameters are obtained in descending order
    of preference from these sources:

    1. overrides[key]               only if overrides != None
    2. defaults[key]                only if defaults != None
    3. webauthn2_config.json[key]   only if defaults == None and jsonFileName is a readable file
    4. built_ins[key]

    The built-in defaults (4) are safe and harmless, using the
    'null' providers and requiring authentication context that
    these providers will never receive.  Thus, the properly
    written application service will not function until a better
    configuration is chosen.

    The application can suppress any built-in defaults (4) by
    including all relevant settings in (1)-(3).

    The application can suppress use of the JSON config file (3)
    in the service home directory by passing a dictionary as
    defaults (even if the dictionary is empty).
    
    """
    if defaults is None and jsonFileName is not None:
        if jsonFileName[0:1] == '/':
            fname = jsonFileName
        else:
            homedir = os.environ.get('HOME', './')
            fname = '%s/%s' % (homedir, jsonFileName)
        f = open(fname)
        s = f.read()
        f.close()
        defaults = jsonReader(s)
        if type(defaults) != dict:
            raise TypeError('%r' % defaults)

    config = web_storage()
    config.update(built_ins)
    if defaults:
        config.update(defaults)
    if overrides:
        config.update(overrides)
    return config
    

def string_wrap(s, escape='\\', protect=[]):
    s = s.replace(escape, escape + escape)
    for c in set(protect):
        s = s.replace(c, escape + c)
    return s

def sql_identifier(s):
    # double " to protect from SQL
    return '"%s"' % string_wrap(s, '"') 

def sql_literal(v):
    if v != None:
        # double ' to protect from SQL
        s = '%s' % v
        return "'%s'" % string_wrap(s, "'")
    else:
        return 'NULL'

def is_authorized(context, acl):
    return set( acl ).intersection( set([a['id'] for a in context.attributes]).union( set('*') ) ) \
        and True \
        or False

def urlquote(url, safe=""):
    "common URL quote mechanism for URL value embeddings"
    return urllib.parse.quote(url, safe=safe)

def urlunquote(url):
    "common URL unquote mechanism for URL value embeddings"
    return urllib.parse.unquote_plus(url)

def urlunquote_webpy(url):
    "common URL unquote mechanism for URL value embeddings"
    # this hack works around broken URL decoding already done by web.py which somehow cast UTF-8 buffer as str w/o decoding
    return url.encode('latin1').decode()

def expand_relative_url(path):
    if path == None:
        return None
    path = path.strip()
    if path[0] == '/':
        return "{prot}://{host}{path}".format(
            prot=flask.request.scheme,
            host=flask.request.host,
            path=path
        )
    return path

def generate_random_string(length=24, alpha=True, numeric=True, symbols=False, source=None):
    """
    Generate a random string of given length using selected char sets.

    If source != None, it is used as the source of chars. Otherwise,
    it is built using the combination of alphabetic, numeric, and
    symbol chars designated by the other boolean options.

    """
    if not source:
        source = []
        if alpha:
            source += list('abcdefghijklmnopqrstuvwxyz'
                           + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        if numeric:
            source += list('0123456789')

        if symbols:
            source += list('!$&*,.:;')

    return ''.join([ source[random.randrange(0, len(source))]
                     for i in range(0, length) ])

class Context (object):
    """
    A Context instance represents authentication context for a single service request.

    Each request context includes these important fields:

        context.session     exposes session information or is None 
        context.client      exposes name-value pairs associated with the client
        context.attributes  exposes a set of client attributes
        context.tracking    exposes a tracking ID or is None

    The non-None session object should always implement interfaces
    consistent with the Session class.  It may support additional
    provider-specific capabilities.

    The client value should either be None or a dict.
    Each attribute value should be a dict.

    The client and attribute dicts should have the form:

      {'id': ..., 'display_name': ... }

    and may have additional, provider-specific information fields.

    """

    def __init__(self, manager=None, setheader=False, conn=None, cur=None):
        """
        Construct one Context instance using the manager and setheader policy as needed.

        The manager is included to provide reentrant access to the
        configured providers for this webauthn deployment.

        """
        self.session = None
        self.attributes = set()
        self.client = None
        self.tracking = None
        self.extra_values = dict()

        if manager:
            # look for existing session ID context in message
            if manager.sessionids:
                sessionids = manager.sessionids.get_request_sessionids(manager, self, conn, cur)
            else:
                sessionids = set()

            if sessionids:
                # look up existing session data for discovered IDs
                if manager.sessions:
                    manager.sessions.set_msg_context(manager, self, sessionids, conn, cur)

            if manager.clients.msgauthn:
                # look for embedded client identity
                oldclient = self.get_client_id()

                manager.clients.msgauthn.set_msg_context(manager, self, conn, cur)

                if oldclient != self.get_client_id() and manager.attributes.client:
                    # update attributes for newly modified client ID
                    self.attributes = set()
                    manager.attributes.client.set_msg_context(manager, self, conn, cur)

            if manager.attributes.msgauthn:
                # look for embedded client attributes
                manager.attributes.msgauthn.set_msg_context(manager, self, conn, cur)

    @property
    def client_id(self):
        """Get self.client.id value or None if client is unknown."""
        return self.client.get('id') if self.client is not None else None

    def get_client_id(self):
        """Backwards-compatibility alias for self.client_id property."""
        return self.client_id

    @property
    def attribute_ids(self):
        """Flat list of each attr.id for attr in self.attributes, e.g. to compare to ACLs.

        This list ignores attributes which lack an 'id' field or where
        the value is None.

        """
        return [ a.get('id') for a in self.attributes if a.get('id') is not None ]

    def __repr__(self):
        return '<%s %s>' % (
            type(self),
            dict(
                session=self.session,
                client=self.client,
                attributes=self.attributes,
                tracking=self.tracking,
                extra_values=self.extra_values
            )
        )

def session_from_environment():
    """
    Get and decode session details from the environment set by the http server (with mod_webauthn).
    Returns a dictionary on success, None if the environment variable is unset (or blank).
    Throws TypeError if the base64 decode fails and ValueError if json decode fails
    """
    b64_session_string = None
    try:
        b64_session_string = flask.request.environ['WEBAUTHN_SESSION_BASE64']
    except:
        b64_session_string = os.environ.get('WEBAUTHN_SESSION_BASE64')

    if b64_session_string == None or b64_session_string.strip() == '':
        return None
    session_string=base64.standard_b64decode(b64_session_string).decode()
    return jsonReader(session_string)

def context_from_environment(fallback=True):
    """
    Get and decode session details from the environment set by the http server (with mod_webauthn).
    Returns a Context instance which may be empty (anonymous).
    If fallback=False, returns None if context was not found in environment.
    Throws TypeError if the base64 decode fails and ValueError if json decode fails
    """
    context_dict = session_from_environment()
    context = Context()
    if context_dict:
        context.client = context_dict['client']
        context.attributes = context_dict['attributes']
        context.session = {
            k: v
            for k, v in context_dict.items()
            if k in {'since', 'expires', 'seconds_remaining', 'vary_headers'}
        }
        context.tracking = context_dict.get('tracking')
        return context
    elif fallback:
        return context
    else:
        return None


class NoMethod(web.HTTPError):
    """`405 Method Not Allowed` error."""
    message = "method not allowed"
    def __init__(self, message=None):
        status = '405 Method Not Allowed'
        headers = {'Content-Type': 'text/html'}
        web.HTTPError.__init__(self, status, headers, message or self.message)

class Conflict(web.HTTPError):
    """`409 Conflict` error."""
    message = "conflict"
    def __init__(self, message=None):
        status = '409 Conflict'
        headers = {'Content-Type': 'text/html'}
        web.HTTPError.__init__(self, status, headers, message or self.message)

class Forbidden(web.HTTPError):
    """`403 Forbidden` error."""
    message = "forbidden"
    def __init__(self, message=None):
        status = '403 Forbidden'
        headers = {'Content-Type': 'text/html'}
        web.HTTPError.__init__(self, status, headers, message or self.message)

class Unauthorized(web.HTTPError):
    """`401 Unauthorized` error."""
    message = "unauthorized"
    def __init__(self, message=None):
        status = '401 Unauthorized'
        headers = {'Content-Type': 'text/html'}
        web.HTTPError.__init__(self, status, headers, message or self.message)

class NotFound(web.HTTPError):
    """`404 Not Found` error."""
    message = "not found"
    def __init__(self, message=None):
        status = '404 Not Found'
        headers = {'Content-Type': 'text/html'}
        web.HTTPError.__init__(self, status, headers, message or self.message)

class BadRequest(web.HTTPError):
    """`400 Bad Request` error."""
    message = "bad request"
    def __init__(self, message=None):
        status = '400 Bad Request'
        headers = {'Content-Type': 'text/html'}
        web.HTTPError.__init__(self, status, headers, message or self.message)

class PooledConnection (object):
    """
    Abstract base class for pooled connection instances that reuse connections.

    Multiple global pools are maintained, one per unique config_tuple
    key, to disambiguate similar but different connections.

    The actual connection is an opaque value and can be any value
    created by the derived class's _new_connection() method.

    """

    pools = {}

    def __init__(self, config_tuple):
        """Create a pooled connection instance with config_tuple as pool key."""
        self.config_tuple = config_tuple

    def _get_pooled_connection(self):
        """Get a pooled connection from the keyed pool or create one on demand."""
        pool = PooledConnection.pools.get(self.config_tuple, set())
        try:
            connection = pool.pop()
        except KeyError:
            connection = self._new_connection()
        return connection

    def _put_pooled_connection(self, connection):
        """Return a connection instance to the pool for future use."""
        pool = PooledConnection.pools.setdefault(self.config_tuple, set())
        pool.add(connection)

    def _new_connection(self):
        """Create an actual connection object (abstract base method)."""
        raise NotImplementedError()

    def _close_connection(self, conn):
        """Close an actual connection previously opened."""
        pass

def force_query(conn, cur, *args, **kwargs):
    """Force cur.query SELECT generator results as expected by legacy code here."""
    cur.execute(*args, **kwargs)
    return list(cur)

class AttrDictRow (psycopg2.extras.DictRow):
    """A row object to allow row.columname access as well as dict and tuple access.

    Tweaks the normal psycopg2.extras.DictRow to also allow
    attribute-style access to columns, but will not shadow actual
    python object attributes. Use the dict or tuple-style access or
    rewrite your queries to avoid such collisions.

    This access is ONLY for reading a specific field by name as a
    compatibility shim. Do not try to set field values via attribute
    assignment nor to discover field names by introspection with
    dir(row)!

    It would be better to migrate consumers to use the dict or tuple
    access methods, inherited from the superclass, and eventually
    deprecate this attribute-based access mechanism.

    """
    def __getattribute__(self, a):
        g = super().__getattribute__
        try:
            # real attributes take precedence
            return g(a)
        except AttributeError:
            try:
                return self[a]
            except KeyError:
                raise AttributeError(a)

class AttrDictCursor(psycopg2.extras.DictCursor):
    """A cursor that produces AttrDictRow rather than DictRow instances."""
    def __init__(self, *args, **kwargs):
        # DictCursor.__init__ blindly sets its own row_factor kwarg
        super().__init__(*args, **kwargs)
        # so, override where it is saved in DictCursorBase instead...
        self.row_factory = AttrDictRow

class DatabaseConnection (PooledConnection):
    """
    Concrete base class for pooled psycopg2 connections.

    Multiple pools are maintained for each dsn
    encountered from the config storage passed to the constructor.

    This class is a useful base class for a request handler
    class that will want to use transactional database queries as part
    of its request handling logic.

    """

    def __init__(self, config, extended_exceptions=None):
        """
        Create a pooled database connection for the config value.

        Required config attributes:

        config.database_type  (e.g. 'postgres')
        config.database_dsn  (e.g. 'dbname=myapp1' or 'host=... user=... password=... dbname=...')
        config.database_schema  (e.g. 'public' or None)
        config.database_max_retries  (e.g. 5)

        """
        if config.database_type != 'postgres':
            raise NotImplementedError('webauthn2 only supports database_type="postgres"')

        config_tuple = (config.database_dsn,)
        super(DatabaseConnection, self).__init__(config_tuple)

        self.database_dsn = config_tuple[0]
        self.database_schema = config.database_schema
        self.database_max_retries = max(config.database_max_retries, 0)

        if extended_exceptions:
            self.extended_exceptions = extended_exceptions
        else:
            self.extended_exceptions = []

    def _new_connection(self):
        return psycopg2.connect(
            dsn=self.database_dsn,
            cursor_factory=AttrDictCursor,
        )

    def _close_connection(self, conn):
        del conn

    def _db_wrapper(self, db_thunk):
        """
        Run db_thunk(conn) with automatic transaction handling.

        A pooled conn is obtained from self._get_pooled_connection() and
        returned with self._put_pooled_connection(conn).

        A transaction is started before db_thunk(conn) and committed
        before returning thunk results. A web.SeeOther is caught to
        commit the transaction and then re-raised as a psuedo return
        value.

        Several transient exceptions are caught
        (psycopg2.InterfaceError, psycopg2.IntegrityError,
            psycopg2.extensions.TransactionRollbackError), rolling
        back the transaction and trying again with exponential backoff
        delays.  The thunk should not raise IOError as a permanent
        error, but instead map it to some other exception to avoid
        useless retries.

        On too many retries or other exceptions, the original
        exception is re-raised so the caller can optionally do
        something about it or remap it to a more generic error for the
        web etc.

        """
        retries = self.database_max_retries + 1
        conn = None
        last_ev = None

        try:
            while retries > 0:
                if conn is None:
                    conn = self._get_pooled_connection()

                try:
                    with conn.cursor() as cur:
                        val = db_thunk(conn, cur)
                    conn.commit()
                    return val

                except web.SeeOther as ev:
                    conn.commit() # this is a psuedo-exceptional success case
                    raise ev

                except (psycopg2.InterfaceError, psycopg2.OperationalError) as ev:
                    et, ev2, tb = sys.exc_info()
                    deriva_debug('got exception "%s" during _db_wrapper(), retries = %d' % (str(ev2), retries),
                              traceback.format_exception(et, ev2, tb))
                    # abandon stale db connection and retry
                    if conn is not None:
                        self._close_connection(conn)
                    conn = None
                    last_ev = ev

                except (psycopg2.IntegrityError, 
                        psycopg2.extensions.TransactionRollbackError, 
                        IOError, urllib.error.URLError) as ev:
                    et, ev2, tb = sys.exc_info()
                    web.debug('got exception "%s" during _db_wrapper(), retries = %d' % (str(ev2), retries),
                              traceback.format_exception(et, ev2, tb))
                    # these are likely transient errors so rollback and retry
                    conn.rollback()
                    last_ev = ev

                except web.HTTPError as ev:
                    # don't log these "normal" exceptions
                    try:
                        conn.rollback()
                    except:
                        pass
                    raise ev

                except Exception as ev:
                    def trace():
                        et, ev2, tb = sys.exc_info()
                        if tb is not None:
                            deriva_debug('Exception in db_wrapper here: {t}'.format(t=traceback.format_tb(tb)))

                    # see if subclass told us how to handle exception
                    for cls, do_commit, do_trace in self.extended_exceptions:
                        if isinstance(ev, cls):
                            if do_trace:
                                trace()
                            if do_commit:
                                conn.commit()
                            else:
                                try:
                                    conn.rollback()
                                except:
                                    pass
                            raise ev

                    # assume all other exceptions are fatal
                    trace()
                    try:
                        conn.rollback()
                    except:
                        pass
                    raise ev

                retries -= 1

                if retries == 0:
                    # we never get here unless:
                    # 1. an exception prevented 'return val' above
                    # 2. we caught it in an except branch above and it got saved as last_ev for possible retry
                    deriva_debug('giving up with %s after %d retries' % (str(type(last_ev)), self.database_max_retries))
                    raise last_ev
                else:
                    attempt = (retries - self.database_max_retries - 1) * -1
                    delay =  random.uniform(0.75, 1.25) * math.pow(10.0, attempt) * 0.00000001
                    deriva_debug('transaction attempt %d of %d: delaying %f after "%s"' % (attempt, self.database_max_retries, delay, str(last_ev)))
                    time.sleep(delay)

        finally:
            # return conn to pool if we didn't abandon it above
            if conn is not None:
                self._put_pooled_connection(conn)

    def _table(self, tablename):
        """Return sql_identifier(tablename) but qualify with self.database_schema if defined."""
        table = sql_identifier(tablename)
        if self.database_schema:
            return '%s.%s' % (sql_identifier(self.database_schema),
                              table)
        else:
            return table

    def _view_exists(self, conn, cur, tablename):
        """Return True or False depending on whether (schema.)tablename view exists in our database."""

        results = force_query(
            conn, cur,
            """
SELECT * FROM information_schema.views
WHERE table_schema = %(schema)s
  AND table_name = %(table)s
""" % {
    'schema': sql_literal(self.database_schema),
    'table': sql_literal(tablename),
}
        )
        return len(results) > 0
    
    def _table_exists(self, conn, cur, tablename):
        """Return True or False depending on whether (schema.)tablename exists in our database."""

        results = force_query(
            conn, cur,
            """
SELECT * FROM information_schema.tables
WHERE table_schema = %(schema)s
  AND table_name = %(table)s
""" % {
    'schema': sql_literal(self.database_schema),
    'table': sql_literal(tablename),
}
        )
        return len(results) > 0
    
    def _schema_exists(self, conn, cur, schemaname):
        """Return True or False depending on whether schema exists in our database."""

        results = force_query(
            conn, cur,
            """
SELECT * FROM information_schema.schemata
WHERE schema_name = %(schema)s
""" % {
    'schema': sql_literal(schemaname),
}
        )
        return len(results) > 0
    
