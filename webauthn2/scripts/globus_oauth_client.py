import globus_sdk

CLIENT_ID = '8723ca75-ce9d-4966-a906-0361fc556e7c'


client = globus_sdk.NativeAppAuthClient(CLIENT_ID)
client.oauth2_start_flow()

authorize_url = client.oauth2_get_authorize_url()
print('Please go to this URL and login: {0}'.format(authorize_url))
