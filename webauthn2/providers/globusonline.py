"""
Webauthn2 provider implementations using Globus Online GoAuth tokens.

Provider-specific configuration parameters:

`globusonline_nexus_host`
   : Hostname of Nexus auth server. Defaults to the production globusonline server.

`globusonline_nexus_ca`
   : Path to file containing CA certificates to validate the connection to Nexus. No default is provided so the client must specify a CA, or the magic string ":INSECURE:" to disable server verification. This should only be used for testing.

`globusonline_admin_users`
`globusonline_admin_groups`
   : Comma separated list of globusonline usernames/groups that should have admin rights, e.g be able to create catalogs.

"""
import json
import logging
import os.path

from webauthn2.providers.providers import (
    ClientMsgAuthn, ClientProvider,
    AttributeClient, AttributeProvider,
    )
from webauthn2 import exc

import web

from verified_https import VerifiedHTTPSConnection

__all__ = [
    'GlobusOnlineClientProvider',
    'GlobusOnlineAttributeProvider',
    'config_built_ins',
    ]

config_built_ins = web.storage(
    globusonline_nexus_host="nexus.api.globusonline.org",
    globusonline_nexus_ca=None,
    globusonline_admin_groups="",
    globusonline_admin_users="",
    )


AUTHORIZATION_METHOD = "Globus-Goauthtoken"

# TODO: use a logger from the manager or context?
_log = logging.getLogger("webauthn2.providers.globusonline")
_log.setLevel(logging.DEBUG)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
_log.addHandler(_handler)


class GlobusOnlineClientMsgAuthn (ClientMsgAuthn):

    def __init__(self, provider, config):
        ClientMsgAuthn.__init__(self, provider)
        self.config = config

    def set_msg_context(self, manager, context, db=None):
        # make remote calls to globus nexus
        auth_header = web.ctx.env.get("HTTP_AUTHORIZATION")
        if not auth_header:
            _log.debug("no auth header")
            return
        token = _get_token(auth_header)

        admin_groups = self.config.globusonline_admin_groups.split(",")
        admin_users = self.config.globusonline_admin_users.split(",")

        username, groups = _get_user_name_and_groups(
                                self.config.globusonline_nexus_host,
                                token, self.config.globusonline_nexus_ca)
        _log.debug("username = %s", username)
        _log.debug("groups = %s", ", ".join(groups))
        context.client = "u:" + username
        context.globusonline_groups = groups
        context.globusonline_is_admin = (username in admin_users
                                         or (set(groups) & set(admin_groups)))
        _log.debug("Max admin users = %s", admin_users)
        _log.debug("Max users = %s", username)
        _log.debug("Max groups = %s", admin_groups)
        _log.debug("is_admin = %s", context.globusonline_is_admin)


class GlobusOnlineClientProvider (ClientProvider):

    key = 'globusonline'

    def __init__(self, config):
        if not config.globusonline_nexus_host:
            raise exc.ConfigError("Missing required webauthn2 config "
                                 +"`globusonline_nexus_host`")
        if config.globusonline_nexus_ca == ":INSECURE:":
            _log.warn("`globusonline_nexus_ca` is set to ':INSECURE:'; the "
                     +"Nexus server will not be authenticated")
            config.globusonline_nexus_ca = None
        elif config.globusonline_nexus_ca is None:
            raise exc.ConfigError("Missing required webauthn2 config "
                                 +"`globusonline_nexus_ca`.")
        elif not os.path.exists(config.globusonline_nexus_ca):
            raise exc.ConfigError("Configured `globusonline_nexus_ca` "
                                 +"file does not exist.")
        _log.debug("globusonline provider configured successfully")
        ClientProvider.__init__(self, config)
        self.msgauthn = GlobusOnlineClientMsgAuthn(self, config)

    def get_http_vary(self):
        return set(['authorization'])


class GlobusOnlineAttributeClient (AttributeClient):

    def __init__(self, provider):
        AttributeClient.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        context.attributes.add(context.client)
        context.attributes.update(["g:" + group
                                   for group in context.globusonline_groups])
        if context.globusonline_is_admin:
            context.attributes.add("admin")
        _log.debug("attributes = %s", ", ".join(context.attributes))


class GlobusOnlineAttributeProvider (AttributeProvider):

    key = 'globusonline'

    def __init__(self, config):
        AttributeProvider.__init__(self, config)
        self.client = GlobusOnlineAttributeClient(self)


def _get_token(auth_header):
    """
    Get goauth token from the authorization header value, or return None
    if the authorization method is not goauth.
    """
    parts = auth_header.split(None, 1)
    if parts[0] != AUTHORIZATION_METHOD:
        return None
    return parts[1]


def _get_user_name_and_groups(nexus_host, token, nexus_ca=None):
    """
    Contact globus online to get username and groups of the user who
    owns the token. Raises an error if the token is expired or invalid.
    """
    token_dict = dict(field.split("=")
                      for field in token.split("|"))
    username = token_dict["un"]
    path = "/users/%s?fields=username,groups" % username

    headers = dict(
        Authorization="%s %s" % (AUTHORIZATION_METHOD, token),
    )

    # If connection fails, let the exception go through and hit the
    # web.py handler unless the application has setup special handling.
    c = VerifiedHTTPSConnection(host=nexus_host, port=443)
    if nexus_ca:
        c.set_cert(cert_reqs='CERT_REQUIRED', ca_certs=nexus_ca)
    else:
        c.set_cert(cert_reqs='CERT_NONE', ca_certs=None)
    c.request("GET", path, headers=headers)
    r = c.getresponse()
    body = r.read()
    c.close()

    if r.status == 403:
        raise exc.AuthnFailed("Authentication failed")
    elif r.status != 200:
        raise exc.InvalidCredentials("Invalid token")

    parsed = json.loads(body)
    groups = [x["id"] for x in parsed["groups"]]
    groups.append("admin")
    groups.append("g:admin")
    return username, groups
