from requests.auth import HTTPBasicAuth

ta_il_url = 'https://abe-out-il.cs300ohie.net:5000'
auth = HTTPBasicAuth('tutorial', 'pass')
headers = {'Content-Type': 'application/json'}

num_encounters = 5
