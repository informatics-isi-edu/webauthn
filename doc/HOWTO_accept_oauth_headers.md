## Accepting OAUth2 Bearer tokens

Making these changes will cause webauthn to look for HTTP headers of the form "Authorization: Bearer xxxxx") and use them for authentication if found. If no valid header of that format is found (e.g., no Authorization header at all, one with an invalid token, etc.), webauthn will revert to the webcookie / OpenID Connect authentication method used by Chaise and other clients.

1. Decide what scope you want to require for your service. One scope that we've set up already is the generic `https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_all` scope, which will be displayed in the user's consent dialogue as "use Deriva services". A better practice is to set up a host-specific scope (e.g., `https://auth.globus.org/scopes/nih-commons.derivacloud.org/deriva_all`, which can be displayed as a more specific permission, like "use Deriva services on nih-commons.derivacloud.org").

2. Decide what OAuth2 server you trust to provide those tokens.

3. Make three changes to your `webauthn2_config.json` file:

Change the `sessionids_provider` to `oauth2`.

Add an `oauth2_accepted_scopes` provider with the scope name and issuer you decided to accept, e.g.:

```
    "oauth2_accepted_scopes": [
        {
	}	
           "scope" : "https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_all",
	   "issuer" : "https://auth.globus.org"

    ],
```

Add your scope to the list of scopes in the `oauth2_scope` section of your `webauthn_config`. This isn't strictly necessary, but it makes testing easier.

4. Restart httpd.

## Testing with OAuth2 Bearer tokens

To test, first get a token. If you're using Globus as an OAuth2 provider, you can use a program like the one in webauthn2/scripts/globus_oauth_client.py to request a token -- edit the line:

```
client.oauth2_start_flow(requested_scopes="https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_all")
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

There are four steps to adding a host-specific version of an existing scope:

1. Find the Globus Client ID associated with the Globus client that owns the scope. For example, the Deriva scope is owned by the NIH-Commons Globus client; its client id (which you can find at https://auth.globus.org/v2/web/developers) is 0fb084ec-401d-41f4-990e-e236f325010a.

2. Add a TXT record with that client ID to your host's DNS record, like this one:

```
nih-commons.derivacloud.org	text = "0fb084ec-401d-41f4-990e-e236f325010a"
```

3. Using REST or Python API calls:

- Add your host to the scope-owning Globus client (NIH-Commons for the Deriva scope)
- Update the name and description of your new scope

There's a sample Globus client class in webauthn2/scripts/globus_client_util that's a thin wrapper around the Globus python sdk, so one way to do this would be:

```
   client = GlobusClientUtil()
   client.add_fqdn_to_client("my-host.org")
   my_scope = client.get_scopes_by_name("https://auth.globus.org/scopes/my-host.org/deriva_all")[0]
   client.update_scope(my_scope.get("id"),
      {"name" : "Use Deriva services on my-host.org",
       "description" : "Use all Deriva services on my-host.org"
      })
```    
4. Arrange with the Globus team to add the groups scope as a dependent scope to your new host-specific scope

Right now the process is "ask Kyle to add the Globus auth team to add the groups scope as a dependent scope to your newly-created scope". If you've completed steps 1-3 but not this step, you'll be able to do everything (find the user's identity, fill the wallet with tokens for external services) except determine the user's groups.

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

If the dependent token requests succeeds but does not include the scope `urn:globus:auth:scope:auth.globus.org:view_identities`, that scope will need to be added as a dependency to your scope by the Globus team.






