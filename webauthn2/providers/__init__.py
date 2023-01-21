"""
Webauthn2 provider maps.

`sessionids`
   : A map of all available session identifier providers.

`sessionstates`
   : A map of all available session persistence providers.

`clients`
   : A map of all available client identity providers.

`attributes`
   : A map of all available client attribute providers.

`preauths`
   : A map of all available preauth providers.

"""

import traceback

from ..util import web_storage
from . import providers
from . import null
from . import webcookie
from . import database

__doc__ += null.__doc__ + webcookie.__doc__ + database.__doc__

from .providers import Session

__all__ = [
    'sessionids',
    'sessionstates',
    'clients',
    'attributes',
    'preauths',
    'config_built_ins'
    ]

class ProviderMap:

    def __init__(self, providers):
        self.providers = list(providers)
        self.providers_dict = dict([ (p.key, p) for p in providers ])

    def __getitem__(self, key):
        if type(key) == int:
            return self.providers[key]
        else:
            return self.providers_dict[key]

    def add(self, provider):
        if provider not in self.providers:
            self.providers.append(provider)
            self.providers_dict[provider.key] = provider


sessionids =      ProviderMap([ null.NullSessionIdProvider,
                                webcookie.WebcookieSessionIdProvider])

sessionstates =   ProviderMap([ null.NullSessionStateProvider,
                                database.DatabaseSessionStateProvider])
                                

clients =         ProviderMap([ null.NullClientProvider,
                                database.DatabaseClientProvider ])

attributes =      ProviderMap([ null.NullAttributeProvider,
                                database.DatabaseAttributeProvider ])

preauths =        ProviderMap([ null.NullPreauthProvider, database.DatabasePreauthProvider ])

config_built_ins = web_storage()
config_built_ins.update( database.config_built_ins )
config_built_ins.update( webcookie.config_built_ins )
config_built_ins.update( null.config_built_ins )
config_built_ins.update( providers.config_built_ins )

try:
    # conditionalize oauth2 module since it has oddball dependencies
    from . import oauth2
    _enable_oauth2 = True
except:
    traceback.print_exc()
    _enable_oauth2 = False
    
if _enable_oauth2:
    __doc__ += oauth2.__doc__
    sessionids.add(oauth2.OAuth2SessionIdProvider)    
    sessionstates.add(oauth2.OAuth2SessionStateProvider)
    clients.add(oauth2.OAuth2ClientProvider)
    preauths.add(oauth2.OAuth2PreauthProvider)
    config_built_ins.update( oauth2.config_built_ins )

try:
    # conditionalize globus_auth module since it has oddball dependencies
    from . import globus_auth
    _enable_globus_auth = True
except:
    traceback.print_exc()
    _enable_globus_auth = False
    
if _enable_globus_auth:
    __doc__ += globus_auth.__doc__
    clients.add(globus_auth.GlobusAuthClientProvider)
    preauths.add(globus_auth.GlobusAuthPreauthProvider)
    attributes.add(globus_auth.GlobusAuthAttributeProvider)
    sessionstates.add(globus_auth.GlobusAuthSessionStateProvider)
    config_built_ins.update( globus_auth.config_built_ins )
