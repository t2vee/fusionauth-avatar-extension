import os
import json
import whois
import imghdr
import random
import string
import requests
import pydenticon
from os.path import join, dirname
from dotenv import load_dotenv, set_key
from fastapi import FastAPI, File, UploadFile, Response, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fusionauth.fusionauth_client import FusionAuthClient
from werkzeug.utils import secure_filename
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
id_gen = pydenticon.Generator(5, 5)
origins = ["*"]
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)
app.secret_key = os.urandom(24)
UPLOAD_EXTENSIONS = {'.jpg', '.png', '.webp'}
client = FusionAuthClient(os.environ.get('FA_KEY'), os.environ.get('FA_URL'))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

info = [
    {
        'description': 'Congrats! You have made a call to the ore-ink api, Remember this api is only for '
                       't2v.ch and its subsidiaries, is not for public use! If you wish to access my public api you '
                       'can head over to t2v.ch/api. This service requires the use of a dynamic authentication token.'}
]

auth_error = {'error': 'Failed Authentication'}

cf_error = {'error': 'Request to Cloudflare failed. Is Cloudflare down?'}


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


def avatar_error_handler(response):
    a = response['code']
    if int(a) < 3000:
        return True
    return False


def get_user_id(email):
    a = client.retrieve_user_by_email(email)
    k = a.success_response['user']['id']
    return k


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


def file_size_in_mb(bytes_size):
    i = 0
    while bytes_size >= 1024:
        bytes_size /= 1024.
        i += 1
    f = ('%.2f' % bytes_size).rstrip('0').rstrip('.')
    return float(f)


@app.get('/')
@limiter.limit("10/minute")
def home(request: Request):
    return info


# TODO Rewrite Status Checking
@app.get('/api/v1/status/check')
@limiter.limit("50/minute")
async def api_status_get(request: Request, __token__: str = '', s: str = None, u: str = 'https://t2v.ch'):
    if apikeycheck(__token__):
        if s is not None:
            if s != 'external':
                r = requests.get(f"https://{s}/api/status/endpoint")
                return r.status_code
            r = requests.get(f'https://{u}')
            return r.status_code
        return {'error': 'Invalid Domain or Service', 'code': '3010'}
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


# TODO Fix Whois Looup
@app.get('/api/v1/whois/lookup')
def whois_lookup(d: str = None):
    if d is not None:
        w = whois.query(d)
        return w
    return {'error': 'Invalid Domain', 'code': '3009'}


@app.get('/api/v1/blog/posts/{type}/{page}')
def blog_posts_query(page, post_type):
    h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
         'Authorization': f'Bearer {os.environ.get("CF_KEY")}'}
    r = requests.get(
        f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('BI')}"
        f"/values/keys?prefix={post_type}_{page}", headers=h)
    if check_request(r, "cf"):
        return r
    return cf_error


# TODO Finish Blog Post Admin Panel
@app.post('/api/v1/blog/admin/post/create')
def blog_posts_create(__token__: str = '', ):
    cft = apikeycheck(__token__)
    if cft:
        return None
    return auth_error


@app.get('/api/v1/id/u/{email}/inventory/avatar')
def user_avatar(email: str = 'example@example.com'):
    h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
         'Authorization': f'Bearer {os.environ.get("CF_KEY")}'}
    r = requests.get(
        f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('CKP')}"
        f"/values/{email}", headers=h)
    if check_request(r, "cf"):
        avatar = r.text.replace('\\', '')
        return {'response': r'https://{url}/{avatar}'.format(url=os.environ.get('AV_URL'), avatar=avatar.replace('"', ''))}
    return {'response': f'https://{os.environ.get("AV_URL")}/default_av'}


@app.post('/api/v1/id/u/{email}/inventory/avatar_new')
async def user_avatar_new(__token__: str = '', email: str = 'example@example.com', u: UploadFile = File(...)):
    cft = apikeycheck(__token__)
    if cft:
        filename = secure_filename(u.filename)
        img_check = imghdr.what(u.file)
        if filename != '':
            fs = u.file.read()
            if file_size_in_mb(len(fs)) < float(os.environ.get('MUS')):
                file_ext = os.path.splitext(filename)[1]
                if file_ext in UPLOAD_EXTENSIONS:
                    if img_check == file_ext.replace('.', ''):
                        letters = string.ascii_letters
                        kv = ''.join(random.choice(letters) for _ in range(64))
                        h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
                             'Authorization': f'Bearer {os.environ.get("CF_KEY")}',
                             'Content-Type': 'text/plain'}
                        r = requests.put(
                            f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces"
                            f"/{os.environ.get('CKP')}/values/{email}", headers=h, json=f"{kv}{file_ext}")
                        if check_request(r, "cf"):
                            fullfile = os.path.join(os.environ.get('UF'), kv + file_ext)
                            with open(fullfile, "wb+") as fi:
                                fi.write(fs)
                                fi.close()
                                data = {
                                    'user': {
                                        'email': email,
                                        'imageUrl': user_avatar(email)
                                    }
                                }
                                user_id = get_user_id(email)
                                cr = client.update_user(user_id, data)
                                if cr.was_successful():
                                    return {'response': 'Image Uploaded', 'code': '2002'}
                                return {'error': 'Failed to Add Image to User Profile', 'code': '3008'}
                        return {'error': 'Creating File Key Failed', 'code': '3007'}
                    return {'error': 'File is Invalid', 'code': '3006'}
                return {'error': 'File Type Not Allowed', 'code': '3005'}
            return {'error': 'File Too Large', 'code': '3012'}
        return {'error': 'Invalid File Name', 'code': '3004'}
    return auth_error


@app.delete('/api/v1/id/u/{email}/inventory/avatar_delete')
async def user_avatar_delete(__token__: str = '', email: str = 'example@example.com'):
    cft = apikeycheck(__token__)
    if cft:
        f = user_avatar(email)
        os.remove(os.path.join(os.environ.get("UF"), f.replace(f"https://{os.environ.get('AV_URL')}/", '')))
        h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
             'Authorization': f'Bearer {os.environ.get("CF_KEY")}'}
        r = requests.delete(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces"
                            f"/{os.environ.get('CKP')}/values/{email}", headers=h)
        # TODO Change this to use/generate default avatar
        if check_request(r, "cf"):
            data = {
                'user': {
                    'email': email,
                    'imageUrl': f'https://{os.environ.get("AV_URL")}/default_av'
                }
            }
            user_id = get_user_id(email)
            cr = client.update_user(user_id, data)
            if cr.was_successful():
                return {'response': 'Successfully Deleted', 'code': '2001'}
            return {'error': 'Failed to Remove From User Data', 'code': '3002'}
        return {'error': 'Failed to Delete', 'code': '3001'}
    return auth_error


@app.put('/api/v1/id/u/{email}/inventory/avatar_update')
async def user_avatar_update(__token__: str = '', email: str = 'example@example.com', u: UploadFile = File(...)):
    cft = apikeycheck(__token__)
    if cft:
        r = await user_avatar_delete(__token__, email)
        if avatar_error_handler(r):
            r2 = await user_avatar_new(__token__, email, u)
            if avatar_error_handler(r2):
                return {'response': 'Avatar Update Succeeded', 'code': '2003'}
            return {'error': 'Failed to Delete Old Avatar', 'code': '3011'}
        return {'error': 'Failed to Delete Old Avatar', 'code': '3013'}
    return auth_error


@app.post('/api/v1/webhooks/id/avatar/new_default')
async def webhook_avatar_new_default(response: Response, req: Request, auth_token: str | None = Header(None, convert_underscores=True)):
    cft = apikeycheck(auth_token)
    if cft:
        body = await req.json()
        email = body['user']['email']
        identicon = id_gen.generate(email, 240, 240, output_format="png")
        letters = string.ascii_letters
        kv = ''.join(random.choice(letters) for _ in range(64))
        h = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
             'Authorization': f'Bearer {os.environ.get("CF_KEY")}',
             'Content-Type': 'text/plain'}
        r = requests.put(
            f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces"
            f"/{os.environ.get('CKP')}/values/{email}", headers=h, json=f"{kv}.png")
        if check_request(r, "cf"):
            fullfile = os.path.join(os.environ.get('UF'), kv + '.png')
            with open(fullfile, "wb+") as fi:
                fi.write(identicon)
                fi.close()
                data = {
                    'user': {
                        'email': email,
                        'imageUrl': user_avatar(email)['response']
                    }
                }
                user_id = get_user_id(email)
                cr = client.update_user(user_id, data)
                if cr.was_successful():
                    response.status_code = 200
                    return {'response': 'Default Avatar Created', 'code': '2005'}
                response.status_code = 461
                return {'error': 'Failed to Add Image to User Profile', 'code': '3008'}
        response.status_code = 460
        return {'error': 'Creating File Key Failed', 'code': '3007'}
    response.status_code = 401
    return auth_error


# TODO Finish Fusionauth Webhooks
@app.post('/api/v1/webhooks/id/avatar/email_update')
def webhook_avatar_email_update(auth_token: str | None = Header(None, convert_underscores=True)):
    cft = apikeycheck(auth_token)
    if cft:
        return False
    return auth_error


@app.post('/api/v1/webhooks/id/avatar/account_delete')
def webhook_avatar_account_delete(auth_token: str | None = Header(None, convert_underscores=True)):
    cft = apikeycheck(auth_token)
    if cft:
        return False
    return auth_error


@app.api_route("/{path_name:path}", methods=["GET"])
async def catch_all(request: Request, path_name: str):
    return {'error': "Sorry about that but it seems you've hit a dead end! Check the API docs to find your way around "
                     "again"}
