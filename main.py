import requests
import random
import string
import imghdr
import shutil
import whois
import json
import os
from fastapi import FastAPI, File, UploadFile, Form, Response, Request
from dotenv import load_dotenv, set_key
from os.path import join, dirname
from werkzeug.utils import secure_filename

app = FastAPI()
dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)
app.debug = True
app.secret_key = os.urandom(24)
UPLOAD_EXTENSIONS = {'.jpg', '.png', '.webp'}

headers = {"Authorization": os.environ.get('FAAK')}

headers_json = {"content-type": "application/json",
                "Authorization": os.environ.get('FAAK')}

info = [
    {
        'description': 'Congrats! You have made a call to the ore-ink api, Remember this api is only for '
                       't2v.ch and its subsidiaries, is not for public use! If you wish to access my public api you '
                       'can head over to t2v.ch/api. This service requires the use of a dynamic authentication token.'}
]

auth_error = [{'error': 'Failed Authentication'}]

cf_error = [{'error': 'Request to Cloudflare failed. Is Cloudflare down?'}]


def generate_keypairs():
    if os.environ['FTS'] == "False":
        h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
             'Authorization': f'Bearer {os.environ.get("CF_KEY")}',
             'Content-Type': 'application/json'}
        ar = requests.post(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces",
                           headers=h, json={'title': 'apiKeyCheck'})
        br = requests.post(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces",
                           headers=h, json={'title': 'blogIndex'})
        r = requests.post(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces",
                          headers=h, json={'title': 'avatarCdnKeys'})
        p = json.loads(r.text)
        ap = json.loads(ar.text)
        bp = json.loads(br.text)
        k = p['success']
        if k:
            os.environ['CKP'] = p['result']['id']
            set_key(dotenv_path, "CKP", os.environ["CKP"])
            os.environ['TCNSID'] = ap['result']['id']
            set_key(dotenv_path, "TCNSID", os.environ["TCNSID"])
            os.environ['BI'] = bp['result']['id']
            set_key(dotenv_path, "BI", os.environ["BI"])
            os.environ['FTS'] = "True"
            set_key(dotenv_path, "FTS", os.environ["FTS"])
            return "Initial Setup Completed"
        elif p['errors'][0]['code'] == 10014:
            return "Setup Has Already Completed!"
        return "Setup Failed! Is Cloudflare down? Are your details correct?"
    return "Setup Has Already Completed! If this is a Error Change FTS to False in the .env"


print(generate_keypairs())


def apikeycheck(token):
    h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
         'Authorization': f'Bearer {os.environ.get("CF_KEY")}'}
    r = requests.get(
        f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('TCNSID')}/values/{token}",
        headers=h)
    if r.text == token:
        return True
    return False


def check_request(response, call_type):
    if call_type == "cf":
        if response.status_code == 200:
            return True
        return False
    elif call_type == "fa":
        if response != '':
            return True
        return False


@app.get('/')
def home():
    return info


@app.get('/api/v1/status/check')
async def api_status_get(__token__: str = '', s: str = None, u: str = 'https://t2v.ch'):
    if apikeycheck(__token__):
        if s is not None:
            if s != 'external':
                r = requests.get(f"https://{s}/api/status/endpoint")
                return r.status_code
            r = requests.get(f'https://{u}')
            return r.status_code
        return {'error': 'Invalid Domain or Service'}
    return auth_error


@app.get('/api/v1/status/check/all')
def api_status_all(__token__: str = ''):
    cft = apikeycheck(__token__)
    if cft:
        u = ['https://t2v.ch/api/status/endpoint', 'https://ore.ink/api/status/endpoint',
             'https://api.ore.ink/api/status/endpoint', 'https://indentity.t2v.ch/api/status',
             'https://static.t2v-cdn.co/api/status/endpoint', 'https://usercontent.t2v-cdn.co/api/status/endpoint',
             'https://icu.ore.ink/misc/user/logo-header.png?matomo',
             'https://mail.ore.ink/cloud/index.php/apps/theming/image/logoheader?v=42']
        for x in u:
            r = requests.get(x)
            if 400 <= r.status_code <= 600:
                return {'error': 'Not all services are online'}
        return {'response': 'All services are online'}
    return auth_error


@app.get('/api/v1/whois/lookup')
def whois_lookup(d: str = None):
    if d is not None:
        w = whois.query(d)
        return w
    return {'error': 'Invalid Domain'}


@app.get('/api/v1/org/t2v/blog/posts/{type}/{page}')
def blog_posts_query(page, post_type):
    h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
         'Authorization': f'Bearer {os.environ.get("CF_KEY")}'}
    r = requests.get(
        f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('BI')}"
        f"/values/keys?prefix={post_type}_{page}", headers=h)
    if check_request(r, "cf"):
        return r
    return cf_error


@app.post('/api/v1/org/t2v/blog/post/create')
def blog_posts_create():
    return None


@app.get('/api/v1/org/t2v/identity/u/{email}/inventory/')
def user_inv_index(email: str = 'example@example.com'):
    r = [
        {"response": "You can publicly access some user data though this api endpoint"},
        {"Avatar": f"/u/{email}/inventory/avatar"},
        {"Uploads": f"/u/{email}/inventory/uploads"}
    ]
    return r


@app.get('/api/v1/org/t2v/identity/u/{email}/inventory/avatar', response_class=Response)
def user_avatar(email: str = 'example@example.com'):
    h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
         'Authorization': f'Bearer {os.environ.get("CF_KEY")}'}
    r = requests.get(
        f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('CKP')}"
        f"/values/{email}", headers=h)
    if check_request(r, "cf"):
        url = r.text.replace('\\', '')
        return r'https://usercontent.t2v-cdn.co/{url}'.format(url=url.replace('"', ''))
    return {'error': 'This User either does not exist or has not set a avatar'}


@app.post('/api/v1/org/t2v/identity/u/{email}/inventory/avatar/new')
async def user_avatar_new(__token__: str = '', email: str = 'example@example.com', u: UploadFile = File(...)):
    cft = apikeycheck(__token__)
    if cft:
        filename = secure_filename(u.filename)
        if filename != '':
            file_ext = os.path.splitext(filename)[1]
            if file_ext in UPLOAD_EXTENSIONS:
                if imghdr.what(u.file) == file_ext.replace('.', ''):
                    letters = string.ascii_letters
                    kv = ''.join(random.choice(letters) for _ in range(64))
                    h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
                         'Authorization': f'Bearer {os.environ.get("CF_KEY")}',
                         'Content-Type': 'text/plain'}
                    r = requests.put(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces"
                                     f"/{os.environ.get('CKP')}/values/{email}", headers=h, json=kv)
                    if check_request(r, "cf"):
                        fullfile = os.path.join(os.environ.get('UF'), kv)
                        with open(fullfile, "wb+") as fi:
                            fi.write(u.file.read())
                        return {'response': 'Image Uploaded'}
                    return {'error': 'Creating Key Failed'}
                return {'error': 'File is Invalid'}
            return {'error': 'File Type Not Allowed'}
        return {'error': 'Invalid File Name'}
    return auth_error


@app.delete('/api/v1/org/t2v/identity/u/{email}/inventory/avatar/delete')
def user_avatar_delete(__token__: str = '', email: str = 'example@example.com'):
    cft = apikeycheck(__token__)
    if cft:
        f = user_avatar(email)
        os.remove(os.path.join(os.environ.get("UF"), f.replace('https://usercontent.t2v-cdn.co/', '')))
        h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
             'Authorization': f'Bearer {os.environ.get("CF_KEY")}'}
        r = requests.delete(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces"
                            f"/{os.environ.get('CKP')}/values/{email}", headers=h)
        if check_request(r, "cf"):
            return {'response': 'Successfully Deleted'}
        return {'error': 'Failed to Delete'}
    return auth_error


@app.get('/api/v1/org/t2v/identity/u/{email}/dash')
def user_dash_index(__token__: str = '', email: str = 'example@example.com'):
    cft = apikeycheck(__token__)
    if cft:
        u = "https://identity.t2v.ch/api/user?email=" + email
        a = requests.get(u, headers=headers)
        p = json.loads(a.text)
        k = p['user']['id']
    return auth_error


@app.put('/api/v1/org/t2v/identity/u/{email}/dash/update/{update_type}')
def user_dash_update(__token__: str = '', email: str = 'example@example.com', username: str = Form(...),
                     lastname: str = Form(...), firstname: str = Form(...), password: str = Form(...), update_type: str = None):
    cft = apikeycheck(__token__)
    if cft:
        a = requests.get(f"https://identity.t2v.ch/api/user?email={email}", headers=headers)
        p = json.loads(a.text)
        k = p['user']['id']
        if update_type == 'basic_info':
            c = {
                'user': {
                    'firstName': f'{firstname}',
                    'lastName': f'{lastname}',
                    'username': f'{username}',
                }
            }
            requests.put(f"https://identity.t2v.ch/api/user/{k}", data=c, headers=headers_json)
        elif update_type == 'email':
            c = {
                'user': {
                    'email': f'{email}',
                }
            }
            requests.put(f"https://identity.t2v.ch/api/user/{k}", data=c, headers=headers_json)
        elif update_type == 'password':
            c = {
                'user': {
                    'password': f'{password}',
                }
            }
            requests.put(f"https://identity.t2v.ch/api/user/{k}", data=c, headers=headers_json)
    return auth_error


@app.api_route("/{path_name:path}", methods=["GET"])
async def catch_all(request: Request, path_name: str):
    return {'error': "Sorry about that but it seems you've hit a dead end! Check the API docs to find your way around "
                     "again"}
