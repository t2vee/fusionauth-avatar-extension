import os
import json
import whois
import imghdr
import random
import string
import hashlib
import requests
import pydenticon
from PIL import Image
from os.path import join, dirname
from dotenv import load_dotenv, set_key
from fastapi import FastAPI, File, UploadFile, Response, Request, Header, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fusionauth.fusionauth_client import FusionAuthClient
from werkzeug.utils import secure_filename
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
id_gen = pydenticon.Generator(8, 8)
origins = ["*"]
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)
app.secret_key = os.urandom(24)
UPLOAD_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp'}
client = FusionAuthClient(os.environ.get('FA_KEY'), os.environ.get('FA_URL'))
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
auth_error = {'error': 'Failed Authentication'}
cf_error = {'error': 'Request to Cloudflare failed. Is Cloudflare down?'}
cf_headers = {'X-Auth-Email': f'{os.environ.get("CF_EMAIL")}',
              'Authorization': f'Bearer {os.environ.get("CF_KEY")}'}


def generate_keypairs():
    if os.environ['FTS'] == "False":
        ar = requests.post(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces",
                           headers=cf_headers, json={'title': 'apiKeyCheck'})
        br = requests.post(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces",
                           headers=cf_headers, json={'title': 'blogIndex'})
        cr = requests.post(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces",
                           headers=cf_headers, json={'title': 'shortLinkIndex'})
        r = requests.post(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces",
                          headers=cf_headers, json={'title': 'avatarCdnKeys'})
        p = json.loads(r.text)
        ap = json.loads(ar.text)
        bp = json.loads(br.text)
        cp = json.loads(cr.text)
        k = p['success']
        if k:
            os.environ['CKP'] = p['result']['id']
            set_key(dotenv_path, "CKP", os.environ["CKP"])
            os.environ['TCNSID'] = ap['result']['id']
            set_key(dotenv_path, "TCNSID", os.environ["TCNSID"])
            os.environ['BI'] = bp['result']['id']
            set_key(dotenv_path, "BI", os.environ["BI"])
            os.environ['LKI'] = cp['result']['id']
            set_key(dotenv_path, "LKI", os.environ["LKI"])
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
    r = requests.get(
        f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('TCNSID')}/values/{token}",
        headers=cf_headers)
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


def gen_def_av(email):
    identicon = id_gen.generate(email, 240, 240, output_format="webp")
    letters = string.ascii_letters
    kv = ''.join(random.choice(letters) for _ in range(64))
    r = requests.put(
        f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces"
        f"/{os.environ.get('CKP')}/values/{convert_md5(email)}", headers=cf_headers, json=f"{kv}.webp")
    if check_request(r, "cf"):
        fullfile = os.path.join(os.environ.get('UF'), kv + '.webp')
        with open(fullfile, "wb+") as fi:
            fi.write(identicon)
            fi.close()
            data = {
                'user': {
                    'email': email,
                    'imageUrl': user_avatar(convert_md5(email))['response']
                }
            }
            user_id = get_user_id(email)
            cr = client.update_user(user_id, data)
            if cr.was_successful():
                return {'response': 'Default Avatar Created', 'code': 2005}
            return {'error': 'Failed to Add Image to User Profile', 'code': 3008}
    return {'error': 'Creating File Key Failed', 'code': 3007}


def convert_md5(email):
    email_hash = hashlib.md5(email.encode())
    return email_hash.hexdigest()


def convert_to_webp(file):
    c = Image.open(file).convert("RGB")
    c.save()


@app.get('/')
@limiter.limit("100/minute")
def home(request: Request):
    return {'response': 'Welcome to the t2v-main-api, Remember this api is only for t2v.ch and its subsidiaries, '
                        'is not for public use! If you wish to access my public api you can head over to t2v.ch/api.'}


# TODO Rewrite Status Checking to Support Websockets
@app.websocket('/api/v1/websocket/status')
@limiter.limit("50/minute")
async def api_status_get(request: Request, websocket: WebSocket, __token__: str = ''):
    # await websocket.accept()
    # while True:
    return None


# TODO Fix Whois Lookup
@app.get('/api/v1/whois/lookup')
def whois_lookup(d: str = None):
    if d is not None:
        w = whois.query(d)
        return w
    return {'error': 'Invalid Domain', 'code': '3009'}


# TODO Finish Blog Post Admin Panel
@app.get('/api/v1/blog/posts/{type}/{page}')
def blog_posts_query(page, post_type):
    r = requests.get(
        f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('BI')}"
        f"/values/keys?prefix={post_type}_{page}", headers=cf_headers)
    if check_request(r, "cf"):
        return r
    return cf_error


@app.post('/api/v1/blog/admin/post/create')
def blog_posts_create(__token__: str = '', ):
    cft = apikeycheck(__token__)
    if cft:
        return None
    return auth_error


@app.get('/api/v1/id/u/{email_hash}/inventory/avatar')
def user_avatar(email_hash: str = 'example@example.com'):
    r = requests.get(
        f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('CKP')}"
        f"/values/{email_hash}", headers=cf_headers)
    if check_request(r, "cf"):
        avatar = r.text.replace('\\', '')
        return {
            'response': r'https://{url}/{avatar}'.format(url=os.environ.get('AV_URL'), avatar=avatar.replace('"', ''))}
    return {'error': 'Failed to Grab Avatar key', 'code': '3018'}


@app.post('/api/v1/id/u/{email}/inventory/avatar_new')
async def user_avatar_new(__token__: str = '', email: str = 'example@example.com', u: UploadFile = File(...)):
    cft = apikeycheck(__token__)
    if cft:
        # TODO Grab NSFW Check from Client JS
        filename = secure_filename(u.filename)
        img_check = imghdr.what(u.file)
        if filename != '':
            fs = u.file.read()
            if file_size_in_mb(len(fs)) < float(os.environ.get('MUS')):
                file_ext = os.path.splitext(filename)[1]
                if file_ext in UPLOAD_EXTENSIONS:
                    if img_check == file_ext.replace('.', ''):
                        # TODO Resize Image to 256x256 (Presumably Handled by JS)
                        letters = string.ascii_letters
                        kv = ''.join(random.choice(letters) for _ in range(64))
                        r = requests.put(
                            f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('CKP')}/values/{convert_md5(email)}",
                            headers=cf_headers, json=f"{kv}.webp")
                        if check_request(r, "cf"):
                            fullfile = os.path.join(os.environ.get('UF'), kv + '.webp')
                            c = Image.open(u.file).convert("RGB")
                            c.save(fullfile, 'webp')
                            data = {
                                'user': {
                                    'email': email,
                                    'imageUrl': user_avatar(convert_md5(email))['response']
                                }
                            }
                            user_id = get_user_id(email)
                            cr = client.update_user(user_id, data)
                            if cr.was_successful():
                                return {'response': 'Image Uploaded', 'code': 2002}
                            return {'error': 'Failed to Add Image to User Profile', 'code': 3008}
                        return {'error': 'Creating File Key Failed', 'code': 3007}
                    return {'error': 'File is Invalid', 'code': 3006}
                return {'error': 'File Type Not Allowed', 'code': 3005}
            return {'error': 'File Too Large', 'code': 3012}
        return {'error': 'Invalid File Name', 'code': 3004}
    return auth_error


@app.delete('/api/v1/id/u/{email}/inventory/avatar_delete')
async def user_avatar_delete(__token__: str = '', email: str = 'example@example.com', action: str = 'full'):
    cft = apikeycheck(__token__)
    if cft:
        f = user_avatar(convert_md5(email))['response']
        os.remove(os.path.join(os.environ.get("UF"), f.replace(f"https://{os.environ.get('AV_URL')}/", '')))
        r = requests.delete(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces"
                            f"/{os.environ.get('CKP')}/values/{email}", headers=cf_headers)
        if check_request(r, "cf"):
            if action == 'full':
                r = gen_def_av(email)
                if avatar_error_handler(r):
                    return {'response': 'Successfully Deleted', 'code': '2001'}
                return {'error': 'Failed to Remove From User Data', 'code': '3002'}
            else:
                return {'response': 'Successfully Deleted', 'code': '2001'}
        return {'error': 'Failed to Delete', 'code': '3001'}
    return auth_error


@app.put('/api/v1/id/u/{email}/inventory/avatar_update')
async def user_avatar_update(__token__: str = '', email: str = 'example@example.com', u: UploadFile = File(...)):
    cft = apikeycheck(__token__)
    if cft:
        r = await user_avatar_delete(__token__, email, 'full')
        if avatar_error_handler(r):
            r2 = await user_avatar_new(__token__, email, u)
            if avatar_error_handler(r2):
                return {'response': 'Avatar Update Succeeded', 'code': 2003}
            return {'error': 'Failed to Create Avatar', 'code': 3011}
        return {'error': 'Failed to Delete Old Avatar', 'code': 3013}
    return auth_error


@app.post('/api/v1/webhooks/id/avatar/new_default')
async def webhook_avatar_new_default(response: Response, req: Request,
                                     auth_token: str | None = Header(None, convert_underscores=True)):
    cft = apikeycheck(auth_token)
    if cft:
        body = await req.json()
        email = body['event']['user']['email']
        r = gen_def_av(email)
        match r['code']:
            case 3007:
                response.status_code = 460
                return {'error': 'Creating key-pair Failed', 'code': '3022'}
            case 3008:
                response.status_code = 461
                return {'error': 'Failed to add image to user profile', 'code': '3023'}
            case 2005:
                response.status_code = 200
                return {'response': 'default avatar crated', 'code': '2010'}
    return auth_error


@app.post('/api/v1/webhooks/id/avatar/email_update')
async def webhook_avatar_email_update(response: Response, req: Request,
                                      auth_token: str | None = Header(None, convert_underscores=True)):
    cft = apikeycheck(auth_token)
    if cft:
        body = await req.json()
        prev_email = body['event']['previousEmail']
        email = body['event']['user']['email']
        r = requests.get(
            f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces/{os.environ.get('CKP')}"
            f"/values/{prev_email}", headers=cf_headers)
        if check_request(r, "cf"):
            r2 = requests.delete(f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces"
                                 f"/{os.environ.get('CKP')}/values/{convert_md5(prev_email)}", headers=cf_headers)
            if check_request(r2, "cf"):
                avatar = r.text.replace('\\', '')
                avatar2 = avatar.replace('"', '')
                r3 = requests.put(
                    f"{os.environ.get('CF_EP')}accounts/{os.environ.get('CF_AC')}/storage/kv/namespaces"
                    f"/{os.environ.get('CKP')}/values/{convert_md5(email)}", headers=cf_headers, json=avatar2)
                if check_request(r3, "cf"):
                    response.status_code = 200
                    return {'error': 'Email key-pair Updated', 'code': '2006'}
                response.status_code = 462
                return {'error': 'Failed to Delete key-pair', 'code': '3018'}
            response.status_code = 464
            return {'error': 'Failed to update key-pair', 'code': '3020'}
        response.status_code = 463
        return {'error': 'Failed to get key-pair', 'code': '3019'}
    response.status_code = 401
    return auth_error


@app.post('/api/v1/webhooks/id/avatar/account_delete')
async def webhook_avatar_account_delete(response: Response, req: Request,
                                        auth_token: str | None = Header(None, convert_underscores=True)):
    cft = apikeycheck(auth_token)
    if cft:
        body = await req.json()
        email = body['event']['user']['email']
        r = await user_avatar_delete(auth_token, email, 'acc_delete')
        if r['code'] == '2001':
            response.status_code = 200
            return {'error': 'Successfully Deleted', 'code': '2006'}
        response.status_code = 464
        return {'error': 'Failed to delete', 'code': '3021'}
    response.status_code = 401
    return auth_error


@app.api_route("/{path_name:path}", methods=["GET"])
async def catch_all(request: Request, path_name: str):
    return {'error': "Sorry about that but it seems you've hit a dead end! Check the API docs to find your way around "
                     "again"}
