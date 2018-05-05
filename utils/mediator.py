import json
import logging
import requests
import warnings

from uptime import uptime
from .auth import *

def register_mediator(username, password, apiUrl, rejectUnauthorized, mediator_config):
    authenticate(username, apiUrl, rejectUnauthorized)
    auth_headers = generate_auth_headers(username, password)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        response = requests.post('{}/mediators'.format(apiUrl), headers = auth_headers, json=mediator_config, verify=rejectUnauthorized)
    
    if (response.status_code == 201):
        logging.info('Successfully registered mediator.')
    else:
        logging.info(response.status_code)
        logging.info(response)
        raise Exception('Received a non-201 response code, the response body was: {}'.format(response.text))

def send_heartbeat(username, password, apiUrl, rejectUnauthorized, urn, forceConfig):
    url = '{}/mediators/{}/heartbeat'.format(apiUrl, urn)
    headers = generate_auth_headers(username, password)
    json = {
        'uptime': uptime(),
    }

    if (forceConfig):
        json['config'] = True

    logging.info(url)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        response = requests.post(url, headers=headers, json=json, verify=rejectUnauthorized)
<<<<<<< HEAD
    
=======
>>>>>>> 1eb77751c642024a68cf6be1316344ccd07b2850
    if (response.status_code != 200):
        raise Exception('Heartbeat unsuccessful, received status code of {}'.format(response.status_code))
        # logging.info('Heartbeat unsuccessful, received status code of {}'.format(response.status_code))
        return {}

    if (response.reason != 'OK'):
        return response.json()
    else:
        return {}       

def fetch_config(username, password, apiUrl, rejectUnauthorized, urn):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        authenticate(username, apiUrl, rejectUnauthorized)
        new_config = send_heartbeat(username, password, apiUrl, rejectUnauthorized, urn, True)
        logging.info(new_config)

    return new_config

def install_mediator_channels(username, password, apiUrl, rejectUnauthorized, urn, channels=[]):    
    uri = '{}/mediators/{}/channels'.format(apiUrl, urn)
    headers = generate_auth_headers(username, password)
    
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        response = requests.post(uri, headers=headers, json=channels, verify=rejectUnauthorized)
    if (response.status_code == 201):
        logging.info("Channel successfully installed.")
    else:
        logging.info('Received a non-201 response code, the response body was:{}'.format(response.text))