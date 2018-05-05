from requests.auth import HTTPBasicAuth

il_url = 'https://10.147.72.11'

il_channel_port = 5000
il_api_port = 8080

mediator_url = 'http://10.147.72.12'
shr_url = 'http://10.147.72.13'
ta_url = 'http://10.147.72.14'
cr_url = 'http://10.147.72.15'
fr_url = 'http://10.147.72.16'
hwr_url = 'http://10.147.72.17'

auth = HTTPBasicAuth('tutorial', 'pass')
headers = {'Content-Type': 'application/json'}
