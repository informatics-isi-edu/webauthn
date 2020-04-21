
# 
# Copyright 2012-2018 University of Southern California
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
Webauthn2 security context management system.

An application using webauthn2 should at the very minimum instantiate
a manager instance and use it to obtain per-request authentication
context::

  manager = Manager()

  class AppHandler (object):

     def GET(self):
        context = manager.get_request_context()
        # context.client      holds authenticated client identifier
        # context.attributes  holds additional client attributes
        # context.session     holds session information in some scenarios
        ...

However, most applications will also need to export webauthn REST APIs
in order to support client login and session management.  See more
information on the webauthn2.rest module below.

config_built_ins
   The safe, default set of all webauthn2 configuration parameters
   which can be modifed by arguments to the Manager constructor or
   by providing a JSON config file ~/webauthn2_config.json in the
   service home directory.

nullmanager
   A dummy webauthn2 manager using built-in default 'null' providers and configuration.


Top-level configuration parameters (see each sub-module for more
specific configuration parameters:

require_client
   Whether it is an exception to have requests without client identity (boolean).

require_attributes
   Whether it is an exception to have requests without client attributes (boolean).

setheader
   Whether manager.get_request_context() can set response headers by default (boolean).

sessionids_provider
   The key for the provider used to extract session ID info from application request context.

sessionstates_provider
   The key for the provider used to manage session state by session ID.

clients_provider
   The key for the provider used to determine client identities.

preauth_provider
   The key for the provider used to perform pre-authentication.

attributes_provider
   The key for the provider used to determine client attributes.

handler_uri_usersession
   The base URI of RESTful user session management when using RestHandlerFactory.

database_dsn
   The DSN of the database used when creating database connections.

database_type
   The database system name used when creating database connections.

"""

import os.path
import platform
import datetime
import web
from . import util
from . import providers

from .providers.providers import Session, ID
from .util import Context, urlquote

source_checksum = None

__doc__ += providers.__doc__

__all__ = [
    'Manager',
    'Context',
    'nullmanager',
    'config_built_ins'
    ]


config_built_ins = web.storage(
    require_client = True,
    require_attributes = True,
    setheader = False,
    sessionids_provider='null',
    sessionstates_provider='null',
    clients_provider='null',
    attributes_provider='null',
    preauth_provider='null',
    handler_uri_usersession=None,
    extend_session=True
    )

config_built_ins.update(providers.config_built_ins)

class Manager (util.DatabaseConnection):
    """
    A Manager instance provides the main webauthn2 service API.

    An application service usually instantiates one Manager as a
    singleton used by all request processing for the application.  It
    encapsulates a flexible set of providers which implement specific
    aspects of web application security in a composable manner.

    The webauthn2 configuration is set during construction time,
    including content passed as arguments by the application service
    code and/or using environmental defaults found in the application
    service home directory or finally using built-in defaults.

    """

    def __init__(self, overrides=None, defaults=None):
        """
        Construct one Manager instance with given config overrides and defaults.

        The configuration parameters are obtained in descending order
        of preference from these sources:

        1. overrides[key]               only if overrides != None
        2. defaults[key]                only if defaults != None
        3. webauthn2_config.json[key]   only if defaults == None
        4. config_built_ins[key]

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
        # we now ignore config arguments and load dedicated daemon config!
        overrides = util.merge_config(jsonFileName='%s/webauthn2_config.json' % os.path.expanduser("~webauthn"))
        config = util.merge_config(overrides, defaults, built_ins=config_built_ins)

        util.DatabaseConnection.__init__(self, config)

        self.require_client = config['require_client']
        self.require_attributes = config['require_attributes']
        self.setheader = config['setheader']

        self.sessionids = providers.sessionids[config['sessionids_provider']](config)
        self.sessions = providers.sessionstates[config['sessionstates_provider']](config)
        self.clients = providers.clients[config['clients_provider']](config)
        self.attributes = providers.attributes[config['attributes_provider']](config)
        self.preauth = providers.preauths[config['preauth_provider']](config)
        self.config = config
        self.set_discovery_info()

    def set_discovery_info(self):
        self.discovery_info = {}
        for provider in [self.sessionids, self.sessions, self.clients, self.attributes, self.preauth]:
            d = provider.get_discovery_info()
            for key in d.keys():
                self.discovery_info[key] = d[key]
        
    def deploy(self, db=None):
        """
        Perform provider-specific deployment of database content if required.

        """
        for p in [ self.sessionids, self.sessions, self.clients, self.attributes ]:
            if hasattr(p, 'deploy'):
                p.deploy(db)

    def get_request_context(self, require_client=None, require_attributes=None, setheader=None, db=None, extend_session=None):
        """
        Obtain a Context instance summarizing all service request authentication context.

        The optional keyword policy arguments override service
        configuration if they are set to a value other than None.

        require_client = True will raise a ValueError exception if no
           client identity can be established

        require_attributes = True will raise an IndexError exception
           if no client attributes can be established

        setheader = True will allow this call to set web.py response
           headers if necessary for the enabled authentication providers

        """
        if require_client is None:
            require_client = self.require_client
        if require_attributes is None:
            require_attributes = self.require_attributes
        if setheader == None:
            setheader = self.setheader

        if db:
            c = Context(self, setheader, db)
        else:
            c = self._db_wrapper(lambda db: Context(self, setheader, db))

        if require_client and c.get_client_id() == None:
            raise ValueError()
        if require_attributes and len(c.attributes) == 0:
            raise IndexError()

        if extend_session is None:
            extend_session = self.config["extend_session"]

        if extend_session and c.session:
            self.sessions.extend(self, c, db)

        return c
       
    def get_http_vary(self):
        """
        Obtain a set of provider-specific HTTP header names that may affect request context.

        """
        result = set()
        result.update( self.sessionids.get_http_vary() )
        result.update( self.sessions.get_http_vary() )
        result.update( self.clients.get_http_vary() )
        result.update( self.attributes.get_http_vary() )
        return result

    def make_robot_session(self, robot_identity, robot_duration, existing_creds=None):
        """Create robot session returning new credentials or extend existing session returning None.

           If existing_creds are provided, they must resolve to a
           matching session which will simply be extended to the new
           duration.

           If no existing_creds are provided (default), a new session
           is created.

           In either case, the local robot_identity will be qualified
           with an identity authority appropriate to the local
           deployment:  https://local.host.fqdn/webauthn_robot/

        """
        if not self.sessionids or self.sessionids.key != 'webcookie':
            raise NotImplementedError('robot session requires webcookie sessionids provider')
        if not self.sessions:
            raise NotImplementedError('robot session requires sessions provider')

        robot_hostname = platform.node() # host FQDN
        robot_identity_uri = 'https://%s/webauthn_robot/%s' % (robot_hostname, urlquote(robot_identity))

        if existing_creds is not None:
            cred_cookie_hdr = existing_creds[robot_hostname]['cookie']
            cred_cookiename, cred_cookie = cred_cookie_hdr.split('=', 1)
            assert cred_cookiename == self.sessionids.cookiename, 'existing credential cookie name "%s" != configuration "%s"' % (cred_cookiename, self.sessionids.cookiename)

            # attempt to find existing session
            context = Context()
            self.sessions.set_msg_context(self, context, [cred_cookie])
            assert context.session is not None, 'existing credential %s does not match an existing session' % cred_cookie_hdr
            assert context.client['id'] == robot_identity_uri, 'existing session identity "%s" != requested "%s" at hostname %s' % (
                context.client['id'],
                robot_identity,
                robot_hostname
            )

            # extend current session
            self.sessions.extend(self, context, duration=robot_duration)

            return None
        else:
            context = Context()
            context.session = Session(
                since=datetime.datetime.utcnow(),
                expires=datetime.datetime.utcnow() + robot_duration
            )
            self.sessionids.create_unique_sessionids(self, context)

            context.client = {
                'id': robot_identity_uri,
                'display_name': robot_identity,
                'identities': [ robot_identity_uri ],
            }
            context.attributes = [ context.client ]

            self.sessions.new(self, context)
            return {
                robot_hostname: {
                    'cookie': '%s=%s' % (self.sessionids.cookiename, context.session.keys[0])
                }
            }

nullmanager = None

