
# 
# Copyright 2011-2012 University of Southern California
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
Webauthn2 provider implementations using Crowd 2.x SOAP API.

`Crowd2ClientProvider`
   : Client provider 'crowd2' supports APIs for login and search.

`Crowd2AttributeProvider`
   : Attribute provider 'crowd2' supports APIs for client-expansion and search.

Provider-specific configuration parameters:

`crowd_listusers_scope`
   : A list of groups to expand when listing available users to limit scope (list of text).

`crowd_listgroups_scope`
   : A list of groups to expand when listing available groups to limit scope (list of text).

`crowd_max_retries`
   : Maximum number of times to retry SOAP requests on transient errors (int).

`crowd_home_uri`
   : The base URI of the Crowd2 SOAP directory endpoint.

`crowd_app_name`
   : The name of this application when authenticating with the Crowd2 directory endpoint.

`crowd_app_passwd`
   : The secrete of this application when authenticating with the Crowd2 directory endpoint.

"""

from providers import *
from webauthn2.util import *

import web

import sys
import traceback

import re

import suds
import suds.client
import suds.xsd.doctor

config_built_ins = web.storage(
    crowd_listusers_scope= [],
    crowd_listgroups_scope= [],
    crowd_max_retries= 5,
    crowd_home_uri= None,
    crowd_app_name= None,
    crowd_app_passwd= None
    )

__all__ = [
    'Crowd2ClientProvider',
    'Crowd2AttributeProvider',
    'config_built_ins'
    ]

class CrowdApiClient (PooledConnection):

    def __init__(self, config):
        config_tuple = (type(self),
                        config.crowd_home_uri,
                        config.crowd_app_name,
                        config.crowd_app_passwd,
                        frozenset(config.crowd_listusers_scope),
                        frozenset(config.crowd_listgroups_scope),
                        config.crowd_max_retries)
        PooledConnection.__init__(self, config_tuple)

        self.connection_type, \
            self.crowd_home_uri, \
            self.crowd_app_name, \
            self.crowd_app_passwd, \
            self.crowd_listusers_scope, \
            self.crowd_listgroups_scope, \
            self.crowd_max_retries \
            = self.config_tuple
        
        # create a raw client early to force config errors
        self._put_pooled_connection(self._get_pooled_connection())
        
    def _new_connection(self):
        """Make a SOAP client for accessing the Crowd server."""

        # The following dictionary has the targetNamespace as the key and a list
        # of namespaces that need to be imported as the value for that key
        patches = { "urn:SecurityServer": ["http://authentication.integration.crowd.atlassian.com",
                                           "http://soap.integration.crowd.atlassian.com",
                                           "http://exception.integration.crowd.atlassian.com",
                                           "http://rmi.java"] ,
                    "http://soap.integration.crowd.atlassian.com": ["urn:SecurityServer"] }

        # Create an ImportDoctor to use
        doctor = suds.xsd.doctor.ImportDoctor()

        # Patch all the imports into the proper targetNamespaces
        for targetNamespace in patches:
            for nsimport in patches[targetNamespace]:
                imp = suds.xsd.doctor.Import(nsimport)
                imp.filter.add(targetNamespace)
                doctor.add(imp)
                
        soap_client = suds.client.Client(self.crowd_home_uri + 'services/SecurityServer?wsdl', doctor=doctor)

        auth_context = soap_client.factory.create('ns1:ApplicationAuthenticationContext')
        auth_context.name = self.crowd_app_name
        auth_context.credential.credential = self.crowd_app_passwd
        self.token = soap_client.service.authenticateApplication(auth_context)

        return soap_client

    def _soap_wrapper(self, soap_thunk, soap_client_in=None):
        """Run soap_thunk(soap_client) with automatic retry on IOErrors."""

        retries = self.crowd_max_retries + 1

        soap_client = soap_client_in

        while retries > 0:
            try:
                if not soap_client:
                    soap_client = self._get_pooled_connection()
                try:
                    return soap_thunk(soap_client)
                except suds.WebFault, ev:
                    # stale soap client tokens can throw this error...
                    m = re.match('^Server raised fault: \'The application.name or application.password.*does not match.*\'', str(ev))
                    if m:
                        raise IOError(str(ev) + ' or the SOAP connection is stale')
                    et, ev2, tb = sys.exc_info()
                    web.debug('got unhandled suds.WebFault in CrowdApiClient._soap_wrapper(): %s' % str(ev), 
                              traceback.format_exception(et, ev2, tb))
                    raise ev
                finally:
                    if soap_client:
                        self._put_pooled_connection(soap_client)

            except IOError, ev:
                retries -= 1
                if retries == 0:
                    raise ev

    def findAllPrincipalNames(self):
        def thunk(soap_client):
            return soap_client.service.findAllPrincipalNames(self.token)
        return self._soap_wrapper(thunk)

    def findAllGroupNames(self):
        def thunk(soap_client):
            return soap_client.service.findAllGroupNames(self.token)
        return self._soap_wrapper(thunk)

    def findPrincipalByName(self, username):
        def thunk(soap_client):
            try:
                return soap_client.service.findPrincipalByName(self.token, username)
            except suds.WebFaulse, ev:
                m = re.match('^Server raised fault: \'Failed to find entity of type \[com.atlassian.crowd.integration.model.user.User\] with identifier \[.*\]\'', str(ev))
                if m:
                    raise KeyError(str(ev))
                raise ev
        return self._soap_wrapper(thunk)

    def findGroupByName(self, groupname):
        def thunk(soap_client):
            return soap_client.service.findGroupByName(self.token, groupname)
        return self._soap_wrapper(thunk)

    def findGroupMemberships(self, username):
        def thunk(soap_client):
            return soap_client.service.findGroupMemberships(self.token, username).string
        return self._soap_wrapper(thunk)

    def authenticatePrincipal(self, username, password):
        def thunk(soap_client):
            auth_context = soap_client.factory.create('ns1:UserAuthenticationContext')
            auth_context.application = self.crowd_app_name
            auth_context.name = username
            auth_context.credential.credential = password

            try:
                return soap_client.service.authenticatePrincipal(self.token, auth_context)
            except suds.WebFault, ev:
                m = re.match('^Server raised fault: \'Failed to authenticate principal, .*invalid.*\'', str(ev))
                if m:
                    raise ValueError(str(ev))
                m = re.match('^Server raised fault: \'User with username.*does not exist.*\'', str(ev))
                if m:
                    raise KeyError(str(ev))
                m = re.match('^Server raised fault: \'.*User does not have access to application.*\'', str(ev))
                if m:
                    raise KeyError(str(ev))
                raise ev
        return self._soap_wrapper(thunk)

class Crowd2Login (ClientLogin):

    def __init__(self, provider):
        ClientLogin.__init__(self, provider)

    def login(self, manager, context, db, **kwargs):
        """
        Return username if the user can be logged in using 'username' and 'password' keyword arguments.

        Raises TypeError if either keyword argument is absent.
        Raises KeyError if username is not found or user cannot use this application.
        Raises ValueError if password and username combination are not valid.

        It is expected that the caller will store the resulting username into context.client for reuse.
        
        """
        try:
            username = kwargs['username']
            password = kwargs['password']
        except KeyError, ve:
            # treat lack of proper kwargs as a type error
            raise TypeError(str(ve))
        token = self.provider.authenticatePrincipal(username, password)
        return username

class Crowd2ClientSearch (ClientSearch):

    def __init__(self, provider):
        ClientSearch.__init__(self, provider)

    def get_all_clients_noauthz(self, manager, context):
        """
        Return set of all available client identifiers drawn from Crowd user names.

        """
        if self.provider.crowd_listusers_scope:
            # scope limited to specified groups
            names = set()
            for group in self.provider.crowd_listusers_scope:
                names.update( set(self.provider.findGroupByName(group).members.string) )
                names.add( group )
            return names
        else:
            # unlimited scope
            return set(self.provider.findAllPrincipalNames().string)

class Crowd2ClientProvider (ClientProvider, CrowdApiClient):

    key = 'crowd2'

    def __init__(self, config):
        ClientProvider.__init__(self, config)
        CrowdApiClient.__init__(self, config)
        self.login = Crowd2Login(self)
        self.search = Crowd2ClientSearch(self)
    
class Crowd2AttributeClient (AttributeClient):

    def __init__(self, provider):
        AttributeClient.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        """Update context.attributes for the contex.client"""
        if context.client != None:
            context.attributes.add( context.client )
            context.attributes.update( set( self.provider.findGroupMemberships(context.client) ) )

class Crowd2AttributeSearch (AttributeSearch):

    def __init__(self, provider):
        AttributeSearch.__init__(self, provider)

    def get_all_attributes_noauthz(self, manager, context, clientnames):
        """
        Return set of all available attributes drawn from Crowd groups plus clientnames.

        """
        attributes = set(clientnames)
        if self.provider.crowd_listgroups_scope:
            # scope limited to specified groups
            for group in self.provider.crowd_listgroups_scope:
                # TODO: find nested groups?
                attributes.add( group )
            return attributes
        else:
            # unlimited scope
            attributes.update( self.provider.findAllGroupNames().string )
            return attributes

class Crowd2AttributeProvider (AttributeProvider, CrowdApiClient):

    key = 'crowd2'

    def __init__(self, config):
        AttributeProvider.__init__(self, config)
        CrowdApiClient.__init__(self, config)
        self.client = Crowd2AttributeClient(self)
        self.search = Crowd2AttributeSearch(self)

