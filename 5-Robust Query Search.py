import base64
import requests
import datetime
from urllib.parse import urlencode


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
            raise Exception('Counld not authenticate client.')
            # return False
# this portion can be improve by using dedicated function for auth
        data = r.json()
        now = datetime.datetime.now()
        self.access_token = data['access_token']
        expires_in = data['expires_in']  # seconds
        self.access_token_expires = now + \
            datetime.timedelta(seconds=expires_in)
        self.access_token_did_expire = access_token_expires < now
        return True

    def get_access_token(self):
        token = self.access_token
        expires = self.access_token_expires
        now = datetime.datetime.now()
        if expires < now or token == None:
            self.perform_auth()
            return self.get_access_token()
        return token

    def get_resource_headers(self):
        access_token = self.get_access_token()
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        return headers

    def get_resource(self, lookup_id, resource_type, version='v1'):
        url = f'https://api.spotify.com/{version}/{resource_type}/{lookup_id}'
        headers = self.get_resource_headers()

        r = requests.get(url, headers=headers)
        if r.status_code not in range(200, 299):
            return{}
        return r.json()

    def get_artist(self, _id):
        return self.get_resource(_id, resource_type='artists')

    def get_album(self, _id):
        return self.get_resource(_id, resource_type='albums')

    def get_playlist(self, _id):
        return self.get_resource(_id, resource_type='playlists')

    def search(self, query, search_type='artist'):
        headers = self.get_resource_headers()
        endpoint = 'https://api.spotify.com/v1/search'
        data = urlencode({'q': query, 'type': search_type.lower()})
        lookup_url = f'{endpoint}?{data}'
        r = requests.get(lookup_url, headers=headers)
        if r.status_code not in range(200, 299):
            return {}
        return r.json()


spotify = SpotifyAPI(client_id, client_secret)
spotify.perform_auth()

access_token = spotify.access_token
