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

import providers
import null
import webcookie
import database
import crowd2
import crowdrest1
import globusonline
import web

__doc__ += null.__doc__ + webcookie.__doc__ + database.__doc__ + crowd2.__doc__

from providers import Session

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
                                database.DatabaseClientProvider,
                                crowd2.Crowd2ClientProvider,
                                crowdrest1.CrowdREST1ClientProvider,
                                globusonline.GlobusOnlineClientProvider ])

attributes =      ProviderMap([ null.NullAttributeProvider,
                                database.DatabaseAttributeProvider,
                                crowd2.Crowd2AttributeProvider,
                                crowdrest1.CrowdREST1AttributeProvider,
                                globusonline.GlobusOnlineAttributeProvider ])

preauths =        ProviderMap([ null.NullPreauthProvider ])

config_built_ins = web.storage()
config_built_ins.update( globusonline.config_built_ins )
config_built_ins.update( crowd2.config_built_ins )
config_built_ins.update( crowdrest1.config_built_ins )
config_built_ins.update( database.config_built_ins )
config_built_ins.update( webcookie.config_built_ins )
config_built_ins.update( null.config_built_ins )
config_built_ins.update( providers.config_built_ins )

try:
    # conditionalize oauth2 module since it has oddball dependencies
    import oauth2
    _enable_oauth2 = True
except:
    _enable_oauth2 = False
    
if _enable_oauth2:
    __doc__ += oauth2.__doc__
    sessionstates.add(oauth2.OAuth2SessionStateProvider)
    clients.add(oauth2.OAuth2ClientProvider)
    preauths.add(oauth2.OAuth2PreauthProvider)
    config_built_ins.update( oauth2.config_built_ins )

try:
    # conditionalize oauth1 module since it has oddball dependencies
    import oauth1a
    _enable_oauth1a = True
except:
    _enable_oauth1a = False
    
if _enable_oauth1a:
    __doc__ += oauth1a.__doc__
    sessionstates.add(oauth1a.Oauth1aSessionStateProvider)
    config_built_ins.update( oauth1a.config_built_ins )

