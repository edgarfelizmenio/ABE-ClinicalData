import threading
import time
import logging
import json

from flask import Flask, make_response

from utils.auth import *
from utils.config import *
from utils.mediator import *

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
# api = Api(app)
appLogger = logging.StreamHandler()
appLogger.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
app.logger.addHandler(appLogger)
app.logger.setLevel(logging.DEBUG)

logging.info('apiConfig: %s', apiConfig)
logging.info('mediatorConfig: %s', mediatorConfig)
logging.info('username: %s', username)
logging.info('password: %s', password)
logging.info('api url: %s', apiUrl)
logging.info('rejectUnauthorized: %s', rejectUnauthorized)
logging.info('urn: %s', urn)
logging.info('port: %s', port)
logging.info('heartbeat interval: %s', heartbeat_interval)

try:
    # register mediator to OpenHIM
    register_mediator(username, password, apiUrl, rejectUnauthorized, mediatorConfig)

    # fetch config from OpenHIM
    new_config = fetch_config(username, password, apiUrl, rejectUnauthorized, urn)
    if (len(new_config) > 0):
        config = new_config

    # install mediator channels
    install_mediator_channels(username, password, apiUrl, rejectUnauthorized, urn, ['ABE Clinical Encounter'])

    # activate heartbeat thread
    def poll_config():
        while True:
            authenticate(username, apiUrl, rejectUnauthorized)
            new_config = send_heartbeat(username, password, apiUrl, rejectUnauthorized, urn, True)
            logging.info("heartbeat: %s", new_config)
            if (len(new_config) > 0):
                config = new_config
            time.sleep(heartbeat_interval)

    heartbeatThread = threading.Thread(target = poll_config) 
    heartbeatThread.start()

except Exception as e:
    logging.error(e)
    exit()

from api.encounters import *

if __name__ == '__main__':
    # do not run on port 80 on development
    if (port != 80):
        app.run(port=port)
    else:
        app.run()