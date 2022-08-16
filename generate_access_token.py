import time
import json
import jwt
import requests
import re

json_filename = 'service-credentials.json'

scopes = 'https://www.googleapis.com/auth/cloud-platform'

expires_in = 3600

def load_json_credentials(filename):
    with open(filename, 'r') as f:
        data = f.read()
    return json.loads(data)

def load_private_key(json_cred):
    return json_cred['private_key']

def create_signed_jwt(pkey, pkey_id, email, scope):
    auth_url = 'https://www.googleapis.com/oauth2/v4/token'
    issued = int(time.time())
    expires = issued + expires_in
    additional_headers = {
            'kid': pkey_id,
            'alg': 'RS256',
            'typ': 'JWT'
            }

    payload = {
        'iss': email,
        'sub': email,
        'aud': auth_url,
        'iat': issued,
        'exp': expires,
        'scope': scope
    }

    sig = jwt.encode(payload, pkey, algorithm='RS256', headers=additional_headers)

    return sig

def exchange_jwt_for_access_token(signed_jwt):
    auth_url = 'https://www.googleapis.com/oauth2/v4/token'
    params = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': signed_jwt
    }

    r = requests.post(auth_url, data=params)

    if r.ok:
        return(r.json()['access_token'], '')

    return None, r.text


def get_access_token():
    cred = load_json_credentials(json_filename)

    private_key = load_private_key(cred)

    s_jwt = create_signed_jwt(
            private_key,
            cred['private_key_id'],
            cred['client_email'],
            scopes)

    token, err = exchange_jwt_for_access_token(s_jwt)
    if token:
        token = re.sub(r'\.{2,}', '', token)
    return token



if __name__ == '__main__':
    print(get_access_token())