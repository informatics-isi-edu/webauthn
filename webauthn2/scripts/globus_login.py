import globus_sdk
import json
import sys
import argparse
from deriva.core import get_oauth_scopes_for_host

CLIENT_ID = '8ef15ba9-2b4a-469c-a163-7fd910c9d111'

def main(host, scope_tag=None):
    client = globus_sdk.NativeAppAuthClient(CLIENT_ID)
    scopes = None
    all_scopes = get_oauth_scopes_for_host(host)
    if all_scopes is None:
        print("can't discover scopes for host '{h}'".format(h=host))
    elif scope_tag:
        scopes = all_scopes.get(scope_tag)
    elif len(all_scopes) == 1:
        scopes = all_scopes.popitem()[1]

    if scopes is None:
        print("couldn't select a scope; the following are the scopes supported by host '{h}'".format(h=host))
        json.dump(all_scopes, sys.stdout, indent=4)
        sys.exit(1)

    print("requesting scopes '{s}'".format(s=scopes))
    client.oauth2_start_flow(requested_scopes=scopes)
    authorize_url = client.oauth2_get_authorize_url(additional_params={"access_type" : "offline"})

    print("Please go to this URL and log in")
    print(authorize_url)
    
    auth_code = input(
        'Please enter the code you get after login here: ').strip()
    token_response = client.oauth2_exchange_code_for_tokens(auth_code)

    print(token_response)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--scope-label", default=None,
                        help="label to sekect when the server supports different (groups of) scopes")
    parser.add_argument("host")
    args = parser.parse_args()
    
    main(args.host, args.scope_label)
