import hashlib
import requests
import warnings
import logging

authUserMap = {}

def authenticate(username, apiURL, rejectUnauthorized):
    requestOptions = {
        'url': '{}/authenticate/{}'.format(apiURL, username),
        'rejectUnauthorized': rejectUnauthorized,
    }
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        response = requests.get(requestOptions['url'], verify = rejectUnauthorized)
    
    if (response.status_code != 200):
        raise Exception('User {} not found when authenticating with core API'.format(username))

    body = response.json()
    authUserMap[username] = body

def generate_auth_headers(username, password):
    user = authUserMap[username]
    salt = user['salt']

    if salt is None:
        raise Exception('{} has not been authenticated. Please authenticate the user first'.format(username)) 

    # create passhash
    now = user['ts']
    shasum = hashlib.sha512()
    shasum.update((salt + password).encode('utf-8'))
    passhash = shasum.hexdigest()

    # create token
    shasum = hashlib.sha512()
    shasum.update((passhash + salt + now).encode('utf-8'))
    token = shasum.hexdigest()

    return {
        'auth-username': username,
        'auth-ts': now,
        'auth-salt': salt,
        'auth-token': token
    }