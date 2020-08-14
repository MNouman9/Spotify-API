import base64
import requests
import datetime


client_id = 'ead3a6962d0b4005a16337fc08962944'
client_secret = '8a27f8fee8ae43cebcfc94888877ce2a'


class SpotifyAPI(object):
    access_token = None
    access_token_expires = datetime.datetime.now()
    access_token_did_expires = True
    client_id = None
    client_secret = None
    token_url = 'https://accounts.spotify.com/api/token'

    def __init__(self, client_id, client_secret, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret

    def get_client_credidentials(self):
        """
        Returns Base64 encoded string
        """
        if self.client_id == None or self.client_secret == None:
            raise Exception('You must set client id and client secret')
        client_creds = f"{self.client_id}:{self.client_secret}"
        client_creds_base64 = base64.b64encode(client_creds.encode())
        return client_creds_base64.decode()

    def get_token_headers(self):
        client_creds_b64 = self.get_client_credentials()
        return {
            "Authorization": F"Basic {client_creds_b64}"
        }

    def get_token_data(self):
        return {
            "grant_type": "client_credentials"
        }

    def perform_auth(self):
        token_data = self.get_token_data()
        token_headers = self.get_token_headers()

        r = requests.post(self.token_url, data=token_data,
                          headers=token_headers)

        # check for valid request
        if r.status_code not in range(200, 299):
            return False
# this portion can be improve by using dedicated function for auth
        data = r.json()
        now = datetime.datetime.now()
        self.access_token = data['access_token']
        expires_in = data['expires_in']  # seconds
        self.access_token_expires = now + \
            datetime.timedelta(seconds=expires_in)
        self.access_token_did_expire = access_token_expires < now
        return True


spotify = SpotifyAPI(client_id, client_secret)
spotify.perform_auth()

spotify.access_token

# spotify.search()
