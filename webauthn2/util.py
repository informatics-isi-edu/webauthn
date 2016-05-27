
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

import psycopg2
import psycopg2.extensions
import web
import urllib
import datetime
import pytz
import math
import random
import time
import itertools
import os
import sys
import traceback
import base64

try:
    import simplejson
    
    jsonWriterRaw = simplejson.dumps
    jsonReader = simplejson.loads
    jsonFileReader = simplejson.load
except:
    import json

    if hasattr(json, 'dumps'):
        jsonWriterRaw = json.dumps
        jsonReader = json.loads
        jsonFileReader = json.load
    else:
        raise ValueError('Could not configure JSON library.')

LOGOUT_URL = "logout_url"
DEFAULT_LOGOUT_PATH = "default_logout_path"

def jsonWriter(o, indent=None):
    def munge(o):
        if isinstance(o, dict) or type(o) == web.Storage:
            return type(o)( itertools.imap( lambda p: (p[0], munge(p[1])),
                                            o.iteritems() ))
        elif hasattr(o, '__iter__'):
            return map( munge, o )
        elif type(o) in [ datetime.datetime, datetime.date ]:
            return str(o)
        #elif hasattr(o, '__dict__'):
        #    return munge(o.__dict__)
        else:
            return o

    return jsonWriterRaw( munge(o), indent=indent )

def negotiated_content_type(supported_types=['text/csv', 'application/json', 'application/x-json-stream'], default=None):
    """Determine negotiated response content-type from Accept header.

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
                q = fields[1]
        return (q, t)

    try:
        accept = web.ctx.env['HTTP_ACCEPT']
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
    Construct web.storage config result from inputs.

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
        homedir = os.environ.get('HOME', './')
        fname = '%s/%s' % (homedir, jsonFileName)
        f = open(fname)
        s = f.read()
        f.close()
        defaults = jsonReader(s)
        if type(defaults) != dict:
            raise TypeError('%r' % defaults)

    config = web.storage()
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
    # double % to protect from web.db
    return '"%s"' % string_wrap(string_wrap(s, '%'), '"') 

def sql_literal(v):
    if v != None:
        # double ' to protect from SQL
        # double % to protect from web.db
        s = '%s' % v
        return "'%s'" % string_wrap(string_wrap(s, '%'), "'")
    else:
        return 'NULL'

def is_authorized(context, acl):
    return set( acl ).intersection( context.attributes.union( set('*') ) ) \
        and True \
        or False

def urlquote(url, safe=""):
    "common URL quote mechanism for URL value embeddings"
    if type(url) not in [ str, unicode ]:
        url = str(url)

    if type(url) == unicode:
        url = url.encode('utf8')

    url = urllib.quote(url, safe=safe)
        
    if type(url) == str:
        url = unicode(url, 'utf8')
        
    return url

def urlunquote(url):
    "common URL unquote mechanism for URL value embeddings"
    if type(url) not in [ str, unicode ]:
        url = str(url)
        
    url = urllib.unquote_plus(url)
    
    if type(url) == str:
        url = unicode(url, 'utf8')

    return url

def expand_relative_url(path):
    if path == None:
        return None
    path = path.strip()
    if path[0] == '/':
        return "{prot}://{host}{path}".format(prot=web.ctx.protocol, host=web.ctx.host, path=path)
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

def session_from_environment():
    """
    Get and decode session details from the environment set by the http server (with mod_webauthn).
    Returns a dictionary on success, None if the environment variable is unset (or blank).
    Throws TypeError if the base64 decode fails and ValueError if json decode fails
    """
    b64_session_string = None
    try:
        b64_session_string = web.ctx.env('WEBAUTHN_SESSION_BASE64')
    except:
        b64_session_string = os.environ.get('WEBAUTHN_SESSION_BASE64')

    if b64_session_string == None or b64_session_string.strip() == '':
        return None
    session_string=base64.standard_b64decode(b64_session_string)
    return jsonReader(session_string)

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
        """Return a SOAP client to the pool for accessing the Crowd server."""
        pool = PooledConnection.pools.setdefault(self.config_tuple, set())
        pool.add(connection)

    def _new_connection(self):
        """Create an actual connection object (abstract base method)."""
        raise NotImplementedError()

class DatabaseConnection (PooledConnection):
    """
    Concrete base class for pooled web.database connections.

    Multiple pools are maintained for each database type/database name
    pair encountered from the config storage passed to the constructor.

    This class is a useful base class for a web.py request handler
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
        config_tuple = (config.database_dsn,
                        config.database_type)
        PooledConnection.__init__(self, config_tuple)

        self.database_schema = config.database_schema
        self.database_max_retries = max(config.database_max_retries, 0)

        self.database_dsn, \
            self.database_type, \
            = self.config_tuple

        if extended_exceptions:
            self.extended_exceptions = extended_exceptions
        else:
            self.extended_exceptions = []

    def _new_connection(self):
        return web.database(dbn=self.database_type, dsn=self.database_dsn)

    def _db_wrapper(self, db_thunk):
        """
        Run db_thunk(db) with automatic transaction handling.

        A pooled db is obtained from self._get_pooled_connection() and
        returned with self._put_pooled_connection(db).

        A transaction is started before db_thunk(db) and committed
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
        db = None
        last_ev = None

        try:
            while retries > 0:
                if db == None:
                    db = self._get_pooled_connection()

                try:
                    t = db.transaction()
                    val = db_thunk(db)
                    t.commit()
                    return val

                except web.SeeOther, ev:
                    t.commit() # this is a psuedo-exceptional success case
                    raise ev

                except psycopg2.InterfaceError, ev:
                    db = None # abandon stale db connection and retry
                    last_ev = ev

                except (psycopg2.IntegrityError, 
                        psycopg2.extensions.TransactionRollbackError, 
                        IOError), ev:
                    et, ev2, tb = sys.exc_info()
                    web.debug('got exception "%s" during _db_wrapper()' % str(ev2),
                              traceback.format_exception(et, ev2, tb))
                    # these are likely transient errors so rollback and retry
                    t.rollback()
                    last_ev = ev

                except web.HTTPError, ev:
                    # don't log these "normal" exceptions
                    try:
                        t.rollback()
                    except:
                        pass
                    raise ev

                except Exception, ev:
                    def trace():
                        et, ev2, tb = sys.exc_info()
                        web.debug('got exception "%s" during _db_wrapper()' % str(ev2),
                                  traceback.format_exception(et, ev2, tb))

                    # see if subclass told us how to handle exception
                    for cls, do_commit, do_trace in self.extended_exceptions:
                        if isinstance(ev, cls):
                            if do_trace:
                                trace()
                            if do_commit:
                                t.commit()
                            else:
                                try:
                                    t.rollback()
                                except:
                                    pass
                            raise ev

                    # assume all other exceptions are fatal
                    trace()
                    try:
                        t.rollback()
                    except:
                        pass
                    raise ev

                retries -= 1

            if retries == 0:
                # we never get here unless:
                # 1. an exception prevented 'return val' above
                # 2. we caught it in an except branch above and it got saved as last_ev for possible retry
                raise last_ev
            else:
                attempt = (retries - self.database_max_retries - 1) * -1
                delay =  random.uniform(0.75, 1.25) * math.pow(10.0, attempt) * 0.00000001
                web.debug('transaction attempt %d of %d: delaying %f after "%s"' % (attempt, self.database_max_retries, delay, str(last_ev)))
                time.sleep(delay)

        finally:
            # return db to pool if we didn't abandon it above
            if db != None:
                self._put_pooled_connection(db)

    def _table(self, tablename):
        """Return sql_identifier(tablename) but qualify with self.database_schema if defined."""
        table = sql_identifier(tablename)
        if self.database_schema:
            return '%s.%s' % (sql_identifier(self.database_schema),
                              table)
        else:
            return table

    def _view_exists(self, db, tablename):
        """Return True or False depending on whether (schema.)tablename view exists in our database."""

        results = db.query("""
SELECT * FROM information_schema.views
WHERE table_schema = %(schema)s
  AND table_name = %(table)s
"""
                           % dict(schema=sql_literal(self.database_schema),
                                  table=sql_literal(tablename))
                           )
        return len(results) > 0
    
    def _table_exists(self, db, tablename):
        """Return True or False depending on whether (schema.)tablename exists in our database."""

        results = db.query("""
SELECT * FROM information_schema.tables
WHERE table_schema = %(schema)s
  AND table_name = %(table)s
"""
                           % dict(schema=sql_literal(self.database_schema),
                                  table=sql_literal(tablename))
                           )
        return len(results) > 0
    
    def _schema_exists(self, db, schemaname):
        """Return True or False depending on whether schema exists in our database."""

        results = db.query("""
SELECT * FROM information_schema.schemata
WHERE schema_name = %(schema)s
"""
                           % dict(schema=sql_literal(schemaname))
                           )
        return len(results) > 0
    
