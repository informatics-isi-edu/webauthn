# Globus Auth Registration

This document goes through the steps to integrate [Globus Auth service](https://www.globus.org/globus-auth-service) with webauthn.


## 1. Create a Globus App (or use an existing one)

The first step is grabbing the Client ID and Client Secret from the [Globus Developers page](https://auth.globus.org/v2/web/developers).


If you're spinning up a new project and want to create a new globus client for it:
  1. On [Globus Developers page](https://auth.globus.org/v2/web/developers).
  2. Click on "Add new app"
     - Don't check the "Native App" button.
     - "App Name" is what will show up on the list on the self-serve page.
     - Assuming your host is `https://example.com`, ensure `https://example.com/authn/session` is included in the redirect URLs. Include any other URLs that are appropriate.
     - Fill in the other fields if desired.
  3. Once the app is created, click the "Generate New Client Secret" and save its value.

If you want to use an existing globus app/client (i.e., service account):

  1. On [Globus Developers page](https://auth.globus.org/v2/web/developers) and find the app that you want to use.
  2. You can see the "Client ID" value
  3. Click on the "Generate New Client Secret" and save its value.
  4. If this is for a new host location, assuming your host is `https://example.com`, ensure `https://example.com/authn/session` is included in the redirect URLs.


## 2. Create the `client_secret_globus.json` on your host

On your host, as the `root` user, create a `client_secret_globus.json` file under `/home/secrets/oauth2/`. Its content should look like the following (use the "Client ID" and "Client Secret" that you grabbed from the previous step):

```
{
  "web": {
    "client_id": "client id value",
    "client_secret": "client secret value"
  }
}
```

Run `restorecon -rv /home/secrets` to ensure this file's permissions are set properly.


## 3. Create scopes for your server

Follow the steps described in [this document](HOWTO_accept_oauth_headers.md) to create a `deriva-all` scope. In short, you need to create a new scope like the following:

```
deriva-globus-auth-utils create-scope "deriva-all" "Main scope for deriva" "deriva_all" --dependent-scope-names "openid,email,profile,urn:globus:auth:scope:auth.globus.org:view_identities,urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships" 
```


### 4. Update `webauthn2_config.json`

Ensure `webauthn2_config.json` (`/home/webauthn/webauthn2_config.json`) has the proper values for the following properties:

- `"sessionids_provider"` must be `"oauth2"`.

- `"oauth2_client_secret_file"` must be  `"/home/secrets/oauth2/client_secret_globus.json"`.

- `"oauth2_accepted_scopes"` and `"oauth2_discovery_scopes"` must refer to the scope created in the previous step.

