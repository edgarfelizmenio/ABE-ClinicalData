import os
import json

def load_json_file(config_file):
    with open(os.path.join('config',config_file)) as config:
        data = json.load(config)
    return data

config = {}
apiConfig = load_json_file("config.json")
mediatorConfig = load_json_file("mediator.json")
username = apiConfig["api"]["username"]
password = apiConfig["api"]["password"]
apiUrl = apiConfig["api"]["apiURL"]
rejectUnauthorized = not bool(apiConfig["api"]["trustSelfSigned"])
urn = mediatorConfig["urn"]
port = int(mediatorConfig["endpoints"][0]["port"])
heartbeat_interval = 10