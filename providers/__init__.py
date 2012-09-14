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

"""

import providers
import null
import webcookie
import database
import crowd2
import web

__doc__ += null.__doc__ + webcookie.__doc__ + database.__doc__ + crowd2.__doc__

from providers import Session

__all__ = [
    'sessionids',
    'sessionstates',
    'clients',
    'attributes',
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

sessionids =      ProviderMap([ null.NullSessionIdProvider,
                                webcookie.WebcookieSessionIdProvider ])

sessionstates =   ProviderMap([ null.NullSessionStateProvider,
                                database.DatabaseSessionStateProvider ])

clients =         ProviderMap([ null.NullClientProvider,
                                database.DatabaseClientProvider,
                                crowd2.Crowd2ClientProvider ])

attributes =      ProviderMap([ null.NullAttributeProvider,
                                database.DatabaseAttributeProvider,
                                crowd2.Crowd2AttributeProvider ])

config_built_ins = web.storage()
config_built_ins.update( crowd2.config_built_ins )
config_built_ins.update( database.config_built_ins )
config_built_ins.update( webcookie.config_built_ins )
config_built_ins.update( null.config_built_ins )
config_built_ins.update( providers.config_built_ins )


