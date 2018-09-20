from globus_sdk import AccessTokenAuthorizer
import sys

class WebauthnClient:
    def __init__(self, host, access_token):
        self.client = AccessTokenAuthorizer(access_token)

    def get_session(self):
        r = self.client.get('https://{host}/authn/session'.format(host=self.host))
        return r.text

if __name__ == '__main__':
    host='webauthn-dev.isrd.isi.edu'
    token=sys.argv[1]
