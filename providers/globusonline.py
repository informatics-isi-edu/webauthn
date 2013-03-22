"""
Webauthn2 provider implementations using Globus Online GoAuth tokens.
"""
import json
import logging

from providers import *
import web

from verified_https import VerifiedHTTPSConnection

__all__ = [
    'GlobusOnlineClientProvider',
    'GlobusOnlineAttributeProvider'
    ]


AUTHORIZATION_METHOD = "Globus-Goauthtoken"

NEXUS_HOST = dict(test="graph.api.test.globuscs.info",
                  qa="graph.api.qa.globuscs.info",
                  prod="nexus.api.globusonline.org")

_log = logging.getLogger("webauthn2.providers.globusonline")
_log.setLevel(logging.DEBUG)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
_log.addHandler(_handler)


class GlobusOnlineClientMsgAuthn (ClientMsgAuthn):

    def __init__(self, provider):
        ClientMsgAuthn.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        # make remote calls to globus nexus
        auth_header = web.ctx.env.get("HTTP_AUTHORIZATION")
        if not auth_header:
            _log.debug("no auth header")
            return
        token = _get_token(auth_header)

        username, groups = _get_user_name_and_groups("test", token)
        _log.debug("username = %s", username)
        _log.debug("groups = %s", ", ".join(groups))
        context.client = username
        context.globus_online_groups = groups


class GlobusOnlineClientProvider (ClientProvider):

    key = 'globusonline'

    def __init__(self, config):
        ClientProvider.__init__(self, config)
        self.msgauthn = GlobusOnlineClientMsgAuthn(self)


class GlobusOnlineAttributeClient (AttributeClient):

    def __init__(self, provider):
        AttributeClient.__init__(self, provider)

    def set_msg_context(self, manager, context, db=None):
        context.attributes.add(context.client)
        context.attributes.update([group
                                   for group in context.globus_online_groups])
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


def _get_user_name_and_groups(deployment, token):
    """
    Contact globus online to get username and groups of the user who
    owns the token. Raises an error if the token is expired or invalid.
    """
    token_dict = dict(field.split("=")
                      for field in token.split("|"))
    username = token_dict["un"]
    host = NEXUS_HOST[deployment]
    path = "/users/%s?fields=username,groups" % username

    headers = dict(
        Authorization="%s %s" % (AUTHORIZATION_METHOD, token),
    )
    c = VerifiedHTTPSConnection(host=host, port=443)
    # TODO: verify server certs for prod
    c.set_cert(cert_reqs='CERT_NONE', ca_certs=None)
    c.request("GET", path, headers=headers)
    r = c.getresponse()
    body = r.read()
    c.close()

    # We got some http response back
    if r.status == 403:
        raise Exception("Auth failed")
    elif r.status != 200:
        raise Exception("Invalid token")

    parsed = json.loads(body)
    groups = [x["id"] for x in parsed["groups"] if x["status"] == "active"]
    return username, groups
