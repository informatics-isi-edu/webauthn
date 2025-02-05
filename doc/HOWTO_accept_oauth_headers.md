## Accepting OAUth2 Bearer tokens

Making these changes will cause webauthn to look for HTTP headers of the form "Authorization: Bearer xxxxx") and use them for authentication if found. If no valid header of that format is found (e.g., no Authorization header at all, one with an invalid token, etc.), webauthn will revert to the webcookie / OpenID Connect authentication method used by Chaise and other clients.

1. Preliminary steps

    Find your client's client id. On ISRD systems, that will be in a file called `/home/secrets/oauth2/client_secret_globus.json`, and the client id is the value of the `client_id` attribute. You can also find it on the [Globus Developers page](https://auth.globus.org/v2/web/developers). Add a DNS text record linking your host's fully qualified domain name to your client ID, like this:
    ```
    webauthn-dev.isrd.isi.edu    text = "576d9c54-0788-4278-bb31-69432e7088ac"
    ```

2. Create a scope for your server. The underlying scope definition sent to the Globus server should look basically like this:
    ```
    {
        "scope": {
            "name": "deriva-all",
            "description": "Main scope for deriva",
            "scope_suffix": "deriva_all",
            "advertised": true,
            "allows_refresh_tokens" : true,
            "dependent_scopes": [
                "openid",
                "email",
                "profile",
                "urn:globus:auth:scope:auth.globus.org:view_identities",
                "urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships"
            ]
        }
    }
    ```
    There are several ways to do this, the following is how you can achieve this with the [deriva-globus-auth-utils](http://docs.derivacloud.org/users-guide/managing-data.html):

    ```
    deriva-globus-auth-utils create-scope "deriva-all" "Main scope for deriva" "deriva_all" --dependent-scope-names "openid,email,profile,urn:globus:auth:scope:auth.globus.org:view_identities,urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships" 
    ```

    When this request succeeds, you'll wind up with two scopes, with names like

    `https://auth.globus.org/scopes/webauthn-dev.isrd.isi.edu/deriva_all`

    and

    `https://auth.globus.org/scopes/576d9c54-0788-4278-bb31-69432e7088ac/deriva-all`

    with `test_scope` replaced with the scope_suffix from the body of the request, the host name replaced with the fully qualified domain name of the host that the request was run from, and the client id replaced with your host's client id.

3. Make three changes to your `webauthn2_config.json` file:

    - Change the `sessionids_provider` to `oauth2`.

    - Add an `oauth2_accepted_scopes` provider with the scope name and issuer you decided to accept, e.g.:

        ```
        "oauth2_accepted_scopes": [
            {
                "scope" : "https://auth.globus.org/scopes/576d9c54-0788-4278-bb31-69432e7088ac/deriva-all",
                "issuer" : "https://auth.globus.org"
            }

        ],
        ```
    - Add the scope to the list of scopes your server advertises (this will cause your server to advertise this information on https://yourhost/authn/discovery, to give clients a hint as to what scopes to request):
        ```
        "oauth2_discovery_scopes" : {
            "deriva-all" : "https://auth.globus.org/scopes/webauthn-dev.isrd.isi.edu/deriva_test_deps_3"
        },
        ```

4. Restart httpd.

## Testing with OAuth2 Bearer tokens

To test, first get a token. If you're using Globus as an OAuth2 provider, you can use `deriva-globus-auth-utils`, like:

```
deriva-globus-auth-utils login --no-local-server --no-browser --hosts my-host.org

```

to request the appropriate scope.

Then, once you have the token, make a request like:

```
    curl -H "Authorization: Bearer _token_" https://my-host/ermrest/catalog/1/schema
```

Make sure there's a `:` after "Authorization" and not after "Bearer". Once you've done that, you can check your session info with:

```
    curl -H "Authorization: Bearer _token_" https://my-host/authn/session
```

## Authenticating outgoing requests

If your service needs to authenticate to an outgoing service (e.g., the Globus identifier service), you'll need to collect credentials to use to authenticate to that service. Globus's implementation of OAuth2 supports the concept of "dependent scopes" -- you can specify (on the Globus server) that a scope (e.g., `https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_all`) depends on having other scopes (e.g., `https://auth.globus.org/scopes/identifiers.globus.org/create_update` and `urn:globus:auth:scope:transfer.api.globus.org:all`) in order to carry out its functions. Webauthn will automatically collect dependent tokens and store them in a wallet associated with the user's session. A service can use the function `deriva.core.utils.webauthn_utils.get_wallet_entries` to get entries of interest from a session wallet.

For example:
```
   wallet = client.extra_values.get("wallet")
   creds = get_wallet_entries(wallet, "oauth2", {"resource_server" : "identifiers.globus.org"})
```

will return something like:

```
[
    {
        "access_token":"xxxxx",
        "expires_in":172800,
         "resource_server":"identifiers.globus.org",
         "token_type":"Bearer",
         "state":"xxxxx",
"scope":"https://auth.globus.org/scopes/identifiers.globus.org/create_update"
    }
]
```

## Adding a host-specific Deriva scope

You can choose to either use one scope for all servers associated with the same Globus client ID (e.g., dev, staging, and production hosts associated with a project), or you can have separate scopes for each host (e.g., have one scope that allows access to the dev server and a different one for the production server). There are four steps to adding a host-specific version of an existing scope:

1. Find the Globus Client ID associated with the Globus client that owns the scope. For example, the Deriva scope is owned by the NIH-Commons Globus client; its client id (which you can find at https://auth.globus.org/v2/web/developers) is 0fb084ec-401d-41f4-990e-e236f325010a.

2. Add a TXT record with that client ID to your host's DNS record, like this one:

```
nih-commons.derivacloud.org	text = "0fb084ec-401d-41f4-990e-e236f325010a"
```

3. Use the [deriva-globus-auth-utils utility or deriva-client API](http://docs.derivacloud.org/users-guide/managing-data.html) to:

- Add your host to the scope-owning Globus client
- Update the name and description of your new scope

## Discovering what scopes a particular host accepts ##

The `/authn/discovery` endpoint (`https://my-host.org/authn/discovery`) will return a structure showing what scopes a server accepts.

## Troubleshooting ##

### Problem: Neither Openid Connect-authenticated sessions nor bearer token-authenticated sessions have group information ###

This probably means that your client (resource server) identity isn't authorized by Globus to get the `urn:globus:auth:scope:auth.globus.org:view_identities` scope. That scope will need to be added to your client by the Globus team.

###  Problem: OpenID Connect-authenticated sessions work fine, but bearer token-authenticated sessions have no group information and have empty wallets ###

Make sure the globus-sdk python library is installed ("pip install globus-sdk"). This will happen automatically on servers built from ISRD recipes after September 20, 2018. If you're missing this library, users will still be able to authenticate using bearer tokens, but bearer-token-authenticated sessions will have empty wallets and group lists, and the message:
```
WARNING: No globus_sdk installed; skipping dependent token request. This means no group info and an empty wallet for sessions authenticated by bearer token.
```
will appear in the server logs each time someone uses a bearer token to authenticate.

###  Problem: OpenID Connect-authenticated sessions work fine, but Bearer-token-authenticated sessions have no group information ###

Make sure the scope that you're using for authentication (which should be in `oauth2_accepted_scopes` in your webauthn_config.json file) is able to retrieve a token with the group scopes. There are some sample test programs in .../webauthn2/scripts that can help with that: globus_oauth_client.py can be used to request a bearer token (be sure to edit the script to specify your scope), and globus_test_client.py can be used to send a dependent tokens request to globus (usage is "python globus_test_client.py _token_"), where _token_ is the token output by globus_oauth_client.py.







