
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

attributes_provider
   The key for the provider used to determine client attributes.

handler_uri_usersession
   The base URI of RESTful user session management when using RestHandlerFactory.

database_name
   The name of the database used when creating database connections.

database_type
   The database system name used when creating database connections.

"""

import web
import util
import providers

from providers import Session

__doc__ += providers.__doc__

__all__ = [
    'Manager',
    'Context',
    'nullmanager',
    'config_built_ins'
    ]

class Context (object):
    """
    A Context instance represents authentication context for a single service request.

    Each request context includes these important fields:

        context.session     exposes session information or is None 
        context.client      exposes client identity or None
        context.attributes  exposes a set of client attributes

    The non-None session object should always implement interfaces
    consistent with the Session class.  It may support additional
    provider-specific capabilities.

    The client value should either be None or a str or unicode text
    value.

    Each attribute value should be a str or unicode text value.

    """

    def __init__(self, manager=None, setheader=False, db=None):
        """
        Construct one Context instance using the manager and setheader policy as needed.

        The manager is included to provide reentrant access to the
        configured providers for this webauthn deployment.

        """
        self.session = None
        self.client = None
        self.attributes = set()

        if manager:
            # look for existing session ID context in message
            if manager.sessionids:
                sessionids = manager.sessionids.get_request_sessionids(manager, self, db)
            else:
                sessionids = set()

            if sessionids:
                # look up existing session data for discovered IDs
                if manager.sessions:
                    manager.sessions.set_msg_context(manager, self, sessionids, db)

            if manager.clients.msgauthn:
                # look for embedded client identity
                oldclient = self.client
                manager.clients.msgauthn.set_msg_context(manager, self, db)

                if oldclient != self.client and manager.attributes.client:
                    # update attributes for newly modified client ID
                    self.attributes = set()
                    manager.attributes.client.set_msg_context(manager, self, db)

            if manager.attributes.msgauthn:
                # look for embedded client attributes
                manager.attributes.msgauthn.set_msg_context(manager, self, db)


    def __repr__(self):
        return '<%s %s>' % (type(self), dict(session=self.session,
                                             client=self.client,
                                             attributes=self.attributes))

config_built_ins = web.storage(
    require_client = True,
    require_attributes = True,
    setheader = False,
    sessionids_provider='null',
    sessionstates_provider='null',
    clients_provider='null',
    attributes_provider='null',
    handler_uri_usersession=None
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
        config = util.merge_config(overrides, defaults, built_ins=config_built_ins)

        util.DatabaseConnection.__init__(self, config)

        self.require_client = config['require_client']
        self.require_attributes = config['require_attributes']
        self.setheader = config['setheader']

        self.sessionids = providers.sessionids[config['sessionids_provider']](config)
        self.sessions = providers.sessionstates[config['sessionstates_provider']](config)
        self.clients = providers.clients[config['clients_provider']](config)
        self.attributes = providers.attributes[config['attributes_provider']](config)
        self.config = config
        
    def deploy(self, db=None):
        """
        Perform provider-specific deployment of database content if required.

        """
        def db_body(db):
            for p in [ self.sessionids, self.sessions, self.clients, self.attributes ]:
                if hasattr(p, 'deploy'):
                    p.deploy(db)

        if db:
            db_body(db)
        else:
            self._db_wrapper( db_body )

    def get_request_context(self, require_client=None, require_attributes=None, setheader=None, db=None, extend_session=True):
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
        if require_client == None:
            require_client = self.require_client
        if require_attributes == None:
            require_attributes = self.require_attributes
        if setheader == None:
            setheader = self.setheader

        if db:
            c = Context(self, setheader, db)
        else:
            c = self._db_wrapper(lambda db: Context(self, setheader, db))

        if require_client and c.client == None:
            raise ValueError()
        if require_attributes and len(c.attributes) == 0:
            raise IndexError()

        if extend_session:
            self.sessions.extend(self, c, db)

        return c
       
nullmanager = Manager()

