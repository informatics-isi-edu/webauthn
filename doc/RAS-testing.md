To use RAS:

0. Make sure your Globus client (the client_id in /home/secrets/oauth2/client_secret_globus.json) is whitelisted for the ras_passport scope.
1. Install the ras-support branch of webauthn
2. Run webauthn2-deploy
3. Copy samples/globus_auth/discovery_globus.json (from the ras-support branch) to /usr/local/etc/oauth2/discovery_globus.json
4. In webauthn2_config.json, add "ras_passport" to the list of scopes in "oauth2_scope".
5. Restart httpd

You can use the ras-support branch with any combination of having/not-having the ras_passport scope inn webauthn2_config.json and being/not-being whitelisted for that scope -- if you don't have both of them, logins will still succeed, but you won't get any RAS info.

To revert back to the master branch:
1. Install the master branch
2. Copy samples/globus_auth/discovery_globus.json (from the master branch) to /usr/local/etc/oauth2/discovery_globus.json
3. Restart httpd.

Other notes:
- has_ras_permissions is true if there are ras permissions, false if there aren't, and not present if we don't have that information.
- Globus doesn't provide a link to log out of RAS. You can delete all \*.nih.gov cookies, which is probably good enough for testing, but of course that doesn't actually invalidate the session.
