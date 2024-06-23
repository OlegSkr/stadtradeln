import os, sys, json, requests, copy, re, codecs
from flask import Flask, request, render_template, redirect
from pathlib import Path
from datetime import datetime
from pymongo import MongoClient
from cryptography.fernet import Fernet


app = Flask(__name__)

strava_url_oauth_token = 'https://www.strava.com/oauth/token'
strava_url_activities = 'https://www.strava.com/api/v3/activities'

path_file = Path(sys.path[0])
datapath = f'{path_file}/data'

def get_json(id:str) -> dict:
    document = mongodb.find_one({ "_id": f"{id}"})
    # TODO: Handle not found case
    utf8encMessage = document["data"]
    encMessage = codecs.encode(utf8encMessage, 'utf-8')
    # print(f'encMessage: {encMessage}')
    decMessage = fernet.decrypt(encMessage).decode()
    # print("decrypted string: ", decMessage)
    json_data = json.loads(decMessage)
    # print('json_data: ', json_data)
    
    return json_data

def save_json(id:str, json_data:dict):
    message = json.dumps(json_data)
    # print('message: ', message)
    encMessage = fernet.encrypt(message.encode())
    utf8encMessage = encMessage.decode(encoding='utf-8', errors='strict')
    document = {
        "_id": f"{id}",
        "data": f"{utf8encMessage}"
    }
    
    # TODO: handle already exists case better
    try:
        mongodb.delete_one({ "_id": f"{id}"})
    except Exception as error:
        print("MongoDB delete Exception (CAN BE IGNORED):", error)

    try:
        result = mongodb.insert_one(document)
        print(f"Inserted document ID: {result.inserted_id}")
    except Exception as error:
        print("MongoDB Exception:", error)
    
client_id = os.environ["client_id"]
client_secret = os.environ["client_secret"]
verify_token = os.environ["verify_token"]
sr_username = os.environ["sr_username"]
sr_password = os.environ["sr_password"]
encryption_key = codecs.encode(os.environ["encryption_key"], 'utf-8')
fernet = Fernet(encryption_key)
mongodb_connection_string = os.environ["mongodb_connection_string"]
mongodb = MongoClient(mongodb_connection_string)['stadtradeln']['credentials']

def create_entry(sr_username, sr_password, entry_date, route_time, route_distance, route_comment):
    try:
    
        session_cookie, user_id = login_stadtradeln(sr_username, sr_password)
        
        add_command = f"curl -s 'https://api.stadtradeln.de/v1/kmbook/{user_id}/add?sr_api_key=aeKie7iiv6ei' "
        add_command += f"-H 'Cookie: {session_cookie}' "
        add_command += f"--data-raw 'entry_id=0&route_movebis_id=&route_is_in_city=0&route_persons=1&route_tracks=1&route_distance={route_distance}&entry_date={entry_date}&route_time={route_time}&route_comment={route_comment}'"
        # print(add_command)
        add_output = os.popen(add_command).read().strip()
        add_json = json.loads(add_output)
    except Exception as error:
        print("Exception 4:", error)

def login_stadtradeln(username:str, password:str):

    login_command = f"curl -is -X POST 'https://login.stadtradeln.de/user/dashboard?L=0&sr_api_key=aeKie7iiv6ei&sr_login_check=1' -d 'sr_auth_action=login&sr_prevent_empty_submit=1&sr_username={username}&sr_password={password}' | grep PHPSESSID" + " | awk {'print $2}'"
    # print(login_command)
    login_output = os.popen(login_command).read().strip()

    kmbook_command = f"curl -is 'https://login.stadtradeln.de/user/kmbook?L=0' -H 'Cookie: {login_output}' | grep 'add?sr_api_key'"
    # print(kmbook_command)
    kmbook_output = os.popen(kmbook_command).read().strip()
    
    result = re.search(r"https:\/\/api.stadtradeln.de\/v1\/kmbook\/(\b\d+)\/add", kmbook_output)
    sr_id = result.group(1)
    print(f'sr_id: {sr_id}')
    
    # Session Cookie and User ID
    return login_output, sr_id

@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/exchange_token', methods=['GET'])
def exchange_token():
    error = request.args.get('error')
    code = request.args.get('code')
    scope = request.args.get('scope')

    if error == 'access_denied':
        return render_template('access_denied.html')

    try:
        authorization_data = get_oauth_token(code)
    except Exception as error:
        print("An exception occurred:", error)

    try:
        athlete_id = authorization_data["athlete"]["id"]
        print(f'GET /exchange_token, athlete_id: {athlete_id}')
        
        if 'athlete' in authorization_data:
            del authorization_data['athlete']

        save_json(athlete_id, authorization_data)
    except Exception as error:
        print("An exception occurred:", error)

    return redirect(f'/connect_stadtradeln?athlete_id={athlete_id}', code=302)

@app.route('/connect_stadtradeln',  methods=['GET', 'POST'])
def connect_stadtradeln():
    
    if request.method == 'GET':
        athlete_id = request.args.get('athlete_id')
        print(f'GET /connect_stadtradeln, athlete_id: {athlete_id}')
        
        return render_template('stadtradeln.html', athlete_id=athlete_id)
        
    elif request.method == 'POST':
        try:
            
            athlete_id = request.form['athlete_id']
            sr_username = request.form['username']
            sr_password = request.form['password']
            
            print(f'POST /connect_stadtradeln, athlete_id: {athlete_id}')
            
            athlete_data = get_json(athlete_id)
            
            athlete_data['sr_username'] = sr_username
            athlete_data['sr_password'] = sr_password

            try:
                # save merged authorization_data with tokens
                save_json(athlete_id, athlete_data)
            except Exception as error2:
                print("An exception occurred:", error2)
            
        except Exception as error:
            print("Exception:", error)
        
        # TODO:
        # render_template('connection_success.html')
        # or
        # redirect(f'/connection_success', code=302) # + add new def/route connection_success
        
        return '', 200

def get_oauth_token(authorization_code:str) -> dict:

    params:dict = {'client_id': f'{client_id}', 'client_secret': f'{client_secret}', 'code': f'{authorization_code}', 'grant_type': 'authorization_code'}
    response:dict = requests.post(strava_url_oauth_token, params=params)

    response.raise_for_status()
    authorization_data = response.json()

    return authorization_data

@app.route('/webhook', methods=['GET', 'POST'])
def webhook():

    if request.method == 'GET':
        
        print('GET /webhook')
        
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        
        if mode == 'subscribe' and token == verify_token:
            return '{"hub.challenge": "' + challenge + '"}'
        else:
            return 'Forbidden', 403
            
    elif request.method == 'POST':

        print('POST /webhook')

        try:
            aspect_type = request.json.get("aspect_type")
        except Exception as error:
            print("An exception occurred:", error)

        try:
            object_id = request.json.get("object_id")
        except Exception as error:
            print("An exception occurred:", error)

        try:
            object_type = request.json.get("object_type")
        except Exception as error:
            print("An exception occurred:", error)

        if object_type != 'activity' or aspect_type != 'create':

            # TODO: Handle updates and deletes

            return '', 200

        try:
            owner_id = request.json.get("owner_id")
        except Exception as error:
            print("An exception occurred:", error)

        try:
            access_token = get_access_token(owner_id)
        except Exception as error:
            print("An exception occurred:", error)

        if object_type == 'activity':
            try:
                activity_data = get_activity_data(access_token, object_id)
                
                athlete_data = get_json(owner_id)
                sr_username = athlete_data['sr_username']
                sr_password = athlete_data['sr_password']
                
                start_date = activity_data['start_date']
                
                date_time_obj = datetime.strptime(start_date[:20], "%Y-%m-%dT%H:%M:%SZ")
    
                entry_date = date_time_obj.strftime("%d.%m.%Y")
                route_time = date_time_obj.strftime("%H:%M:%S")
                
                route_distance = int(int(activity_data['distance']) / 1000)
                
                route_comment = activity_data['name']
                
                create_entry(sr_username, sr_password, entry_date, route_time, route_distance, route_comment)

            except Exception as error:
                print("An exception occurred:", error)

        return '', 200
    else:
        return 'Unimplemented', 501

def get_access_token(athlete_id: str):

    authorization_data = get_json(athlete_id)

    access_token = update_tokens(authorization_data, athlete_id)

    return access_token

def update_tokens(authorization_data:dict, filename:str) -> str:

    access_token = authorization_data['access_token']

    refresh_token = authorization_data['refresh_token']

    try:
        # refreshing tokens if necessary
        params:dict = {'client_id': f'{client_id}', 'client_secret': f'{client_secret}', 'refresh_token': f'{refresh_token}', 'grant_type': 'refresh_token'}
        response:dict = requests.post(strava_url_oauth_token, params=params)

        # if reply Status == 400
        # {"message":"Bad Request","errors":[{"resource":"RefreshToken","field":"refresh_token","code":"invalid"}]}
        response.raise_for_status()

        tokens = response.json()

        # merge authorization_data with new tokens
        authorization_data.update(tokens)

        try:
            # save merged authorization_data with tokens
            save_json(filename, authorization_data)
        except Exception as error2:
            print("An exception occurred:", error2)

        access_token = authorization_data['access_token']

    except Exception as error:
        print("An exception occurred:", error)

    return access_token

def get_activity_data(access_token:str, activity_id:str) -> dict:

    headers:dict = {'Authorization': f'Authorization: Bearer {access_token}'}

    response:dict = requests.get(f'{strava_url_activities}/{activity_id}', headers=headers)

    # if reply Status == 401 (Unauthorized)
    # {"message":"Authorization Error","errors":[{"resource":"Application","field":"","code":"invalid"}]}
    response.raise_for_status()

    activity_data = response.json()
    
    return activity_data
