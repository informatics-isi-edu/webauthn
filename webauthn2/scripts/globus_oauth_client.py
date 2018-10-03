import globus_sdk

CLIENT_ID = 'f7cfb4d6-8f20-4983-a9c0-be3f0e2681fd'

client = globus_sdk.NativeAppAuthClient(CLIENT_ID)
#client.oauth2_start_flow(requested_scopes="https://auth.globus.org/scopes/0fb084ec-401d-41f4-990e-e236f325010a/deriva_all")
client.oauth2_start_flow(requested_scopes="https://auth.globus.org/scopes/nih-commons.derivacloud.org/deriva_all")

authorize_url = client.oauth2_get_authorize_url(additional_params={"access_type" : "offline"})
print('Please go to this URL and login: {0}'.format(authorize_url))


# this is to work on Python2 and Python3 -- you can just use raw_input() or
# input() for your specific version
get_input = getattr(__builtins__, 'raw_input', input)
auth_code = get_input(
    'Please enter the code you get after login here: ').strip()
token_response = client.oauth2_exchange_code_for_tokens(auth_code)

print str(token_response)
nih_commons_data = token_response.by_resource_server['nih_commons']

DERIVA_TOKEN = nih_commons_data['access_token']
print DERIVA_TOKEN
