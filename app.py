import os, sys, json, requests
from flask import Flask, request, render_template
from pathlib import Path
from datetime import datetime

app = Flask(__name__)

print
print
print

print(os.environ)

try:
    strava_url_oauth_token = 'https://www.strava.com/oauth/token'
    strava_url_activities = 'https://www.strava.com/api/v3/activities'
    print(f'strava_url_oauth_token: {strava_url_oauth_token}')
    print(f'strava_url_activities: {strava_url_activities}')
    print
except Exception as error:
    print("Exception 1:", error)

try:
    path_file = Path(sys.path[0])
    print(f'path_file: {path_file}')
    print

    datapath = f'{path_file}/data'
except Exception as error:
    print("Exception 2:", error)

def get_json(filename:str) -> dict:
    with open(f'{datapath}/{filename}.json') as read_file:
        json_data = json.load(read_file)
    return json_data

def save_json(filename:str, json_data:dict):
    with open(f'{datapath}/{filename}.json', 'w') as out_file:
        json.dump(json_data, out_file, sort_keys = True, indent = 4,
            ensure_ascii = False)

try:
    client_id = os.environ["client_id"]
    print(f'client_id: {client_id}')
    print

    client_secret = os.environ["client_secret"]
    print(f'client_secret: {client_secret}')
    print

    verify_token = os.environ["verify_token"]
    print(f'verify_token: {verify_token}')
except Exception as error:
    print("Exception 4:", error)

print
print
print


@app.route('/')
def hello_world():

    print
    print('/hello world')
    print
    try:
        print(f'client_id: {client_id}')
        print(f'client_secret: {client_secret}')
        print(f'verify_token: {verify_token}')
    except Exception as error:
        print("Exception 5:", error)

    return render_template('index.html')

@app.route('/exchange_token', methods=['GET'])
def exchange_token():

    print
    print('/exchange_token')

    error = request.args.get('error')
    code = request.args.get('code')
    scope = request.args.get('scope')
    print(f'error: {error}');
    print(f'code: {code}');
    print(f'scope: {scope}');

    if error == 'access_denied':
        return render_template('access_denied.html')

    try:
        authorization_data = get_oauth_token(code)
        print('authorization_data:')
        print(authorization_data)
        print()
    except Exception as error:
        print("An exception occurred:", error)

    try:
        athlete_id = authorization_data["athlete"]["id"]
        print(f'athlete_id: {athlete_id}')

        save_json(athlete_id, authorization_data)
    except Exception as error:
        print("An exception occurred:", error)


    return '', 200

def get_oauth_token(authorization_code:str) -> dict:

    params:dict = {'client_id': f'{client_id}', 'client_secret': f'{client_secret}', 'code': f'{authorization_code}', 'grant_type': 'authorization_code'}
    response:dict = requests.post(strava_url_oauth_token, params=params)

    response.raise_for_status()
    authorization_data = response.json()

    return authorization_data

@app.route('/webhook', methods=['GET', 'POST'])
def webhook():

    print
    print('/webhook')

    if request.method == 'GET':
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        print('mode: ' + mode);
        print('token: ' + token);
        print('challenge: ' + challenge);
        if mode == 'subscribe' and token == verify_token:
            print('WEBHOOK_VERIFIED');
            return '{"hub.challenge": "' + challenge + '"}'
        else:
            print('Forbidden');
            return 'Forbidden', 403
    elif request.method == 'POST':

        print('DATA POSTED')
        print(request.data)

        try:
            aspect_type = request.json.get("aspect_type")
            print(f'aspect_type: {aspect_type}')
        except Exception as error:
            print("An exception occurred:", error)

        try:
            event_time = request.json.get("event_time")
            print(f'event_time: {event_time}')

            now = datetime.fromtimestamp(event_time)

            year = now.strftime("%Y")
            print("year:", year)

            month = now.strftime("%m")
            print("month:", month)

            day = now.strftime("%d")
            print("day:", day)

            time = now.strftime("%H:%M:%S")
            print("time:", time)

            date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
            print("date and time:",date_time)
        except Exception as error:
            print("An exception occurred:", error)

        try:
            object_id = request.json.get("object_id")
            print(f'object_id: {object_id}')
        except Exception as error:
            print("An exception occurred:", error)

        try:
            object_type = request.json.get("object_type")
            print(f'object_type: {object_type}')
        except Exception as error:
            print("An exception occurred:", error)

        if object_type != 'activity' or aspect_type != 'create':

            # TODO: Handle updates and deletes

            return '', 200

        try:
            owner_id = request.json.get("owner_id")
            print(f'owner_id: {owner_id}')
        except Exception as error:
            print("An exception occurred:", error)

        try:
            subscription_id = request.json.get("subscription_id")
            print(f'subscription_id: {subscription_id}')
        except Exception as error:
            print("An exception occurred:", error)

        try:
            access_token = get_access_token(owner_id)
            print(f'access_token: {access_token}')
        except Exception as error:
            print("An exception occurred:", error)

        if object_type == 'activity':
            try:
                activity_data = get_activity_data(access_token, object_id)
                print(f'activity_data: {activity_data}')

                # Temporarily saving activity data as backup
                save_json(f'{owner_id}_{object_id}', activity_data)

                #####################################################
                #                                                   #
                # TODO: Parse activity and upload to stadtradeln.de #
                #                                                   #
                #####################################################

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

    print
    print('def update_tokens:')
    print
    print('authorization_data: ')
    print(authorization_data)
    print

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
        print('tokens: ')
        print(tokens)
        print

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
