import base64
import requests
import datetime


client_id = 'ead3a6962d0b4005a16337fc08962944'
client_secret = '8a27f8fee8ae43cebcfc94888877ce2a'

# lookup for token
# this is for future requests
client_creds = f"{client_id}:{client_secret}"
client_creds_base64 = base64.b64encode(client_creds.encode())

token_url = 'https://accounts.spotify.com/api/token'
method = 'POST'
token_data = {
    "grant_type": "client_credentials"
}
token_headers = {
    # <base64 encoded client_id:client_secret>
    "Authorization": F"Basic {client_creds_base64.decode()}"
}

r = requests.post(token_url, data=token_data, headers=token_headers)

# check for valid request
if r.status_code in range(200, 299):
    token_response_data = r.json()

    now = datetime.datetime.now()
    access_token = token_response_data['access_token']
    expires_in = token_response_data['expires_in']  # seconds
    expires = now + datetime.timedelta(seconds=expires_in)
    did_expire = expires < now
