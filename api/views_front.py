# cython:language_level=3
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from django.db.models import Q
from django.contrib.auth.decorators import login_required
from django.contrib import auth
from django.urls import reverse # Added for 2FA redirection
from api.models import RustDeskPeer, RustDesDevice, UserProfile, ShareLink, ConnLog, FileLog
from django.forms.models import model_to_dict
from django.core.paginator import Paginator
from django.conf import settings

from itertools import chain
from django.db.models.fields import DateTimeField, DateField, CharField, TextField
import datetime
from django.db.models import Model
import json
import time
import hashlib
import sys
from .forms import AddPeerForm, EditPeerForm, AssignPeerForm

import pyotp
import qrcode
import io
import base64
import hashlib # For hashing recovery codes
import os # For generating random bytes for recovery codes

EFFECTIVE_SECONDS = 7200
OTP_ISSUER_NAME = "RustDeskPro" # You can change this to your app's name
NUMBER_OF_RECOVERY_CODES = 10
RECOVERY_CODE_LENGTH = 10 # Length of each recovery code (e.g. 5_bytes * 2_chars_per_byte = 10_chars)

def getStrSha256(s):
    input_bytes = s.encode('utf-8')
    sha256_hash = hashlib.sha256(input_bytes)
    return sha256_hash.hexdigest()

def model_to_dict2(instance, fields=None, exclude=None, replace=None, default=None):
    """
    :params instance: Model instance, cannot be a queryset
    :params fields: Specifies the fields to display, ('field1','field2')
    :params exclude: Specifies the fields to exclude, ('field1','field2')
    :params replace: Rename the database field names to the required names, {'database_field_name':'frontend_display_name'}
    :params default: Add new field data that doesn't exist, {'field':'data'}
    """
    # Validation for the model instance passed
    if not isinstance(instance, Model):
        raise Exception('model_to_dict expects a model instance')
    # Validation for replacing database field names
    if replace and type(replace) == dict:
        for replace_field in replace.values():
            if hasattr(instance, replace_field):
                raise Exception(f'model_to_dict, the field {replace_field} to be replaced already exists')
    # Validation for adding default values
    if default and type(default) == dict:
        for default_key in default.keys():
            if hasattr(instance, default_key):
                raise Exception(f'model_to_dict, adding a default value for field {default_key} but it already exists')
    opts = instance._meta
    data = {}
    for f in chain(opts.concrete_fields, opts.private_fields, opts.many_to_many):
        # Original code: this part of code would exclude date fields, added a condition to include them
        if not getattr(f, 'editable', False):
            if type(f) == DateField or type(f) == DateTimeField:
                pass
            else:
                continue
        # If fields parameter is passed, it needs to be checked
        if fields is not None and f.name not in fields:
            continue
        # If exclude is passed, it needs to be checked
        if exclude and f.name in exclude:
            continue

        key = f.name
        # Getting the data for the field
        if type(f) == DateTimeField:
            # If the field type is DateTimeField, handle it in a specific way
            value = getattr(instance, key)
            value = datetime.datetime.strftime(value, '%Y-%m-%d')
        elif type(f) == DateField:
            # If the field type is DateField, handle it in a specific way
            value = getattr(instance, key)
            value = datetime.datetime.strftime(value, '%Y-%m-%d')
        elif type(f) == CharField or type(f) == TextField:
            # Check if string data can be serialized into Python structures
            value = getattr(instance, key)
            try:
                value = json.loads(value)
            except Exception as _:
                value = value
        else: # For other types of fields
            key = f.name
            value = f.value_from_object(instance)
        # 1. Replace field names
        if replace and key in replace.keys():
            key = replace.get(key)
        data[key] = value
    # 2. Add new default field data
    if default:
        data.update(default)
    return data

def index(request):
    print('debug',sys.argv)
    if request.user and request.user.username!='AnonymousUser':
        return HttpResponseRedirect('/api/work')
    return HttpResponseRedirect('/api/user_action?action=login')

def user_action(request):
    action = request.GET.get('action', '')
    if action == '':
        return
    if action == 'login':
        return user_login(request)
    if action == 'register':
        return user_register(request)
    if action == 'logout':
        return user_logout(request)

def user_login(request):
    # Handles user login
    if request.method == 'GET':
        return render(request, 'login.html')

    username = request.POST.get('account', '')
    password = request.POST.get('password', '')
    if not username or not password:
        return JsonResponse({'code':0, 'msg':'There was a problem.'})

    user = auth.authenticate(username=username,password=password)
    if user:
        if user.is_2fa_enabled:
            # Store user_id in session to indicate 2FA is pending for this user
            request.session['2fa_user_id_to_verify'] = user.id
            # Return a new response code indicating 2FA is required
            try:
                verify_url = reverse('verify_otp_login')
            except Exception as e: # Fallback if reverse fails for some reason during setup
                print(f"Error reversing URL 'verify_otp_login': {e}")
                verify_url = '/api/verify_otp_login' # Hardcoded fallback
            return JsonResponse({'code': 2, 'msg': 'Please enter your OTP code.', 'url_2fa': verify_url})
        else:
            # 2FA not enabled, log in directly
            auth.login(request, user)
            return JsonResponse({'code':1, 'url': settings.LOGIN_REDIRECT_URL if hasattr(settings, 'LOGIN_REDIRECT_URL') else '/api/work'})
    else:
        return JsonResponse({'code':0, 'msg':'Account or password incorrect!'})

def user_register(request):
    # Handles user registration
    info = ''
    if request.method == 'GET':
        return render(request, 'reg.html')

    result = {
        'code':0,
        'msg':''
    }
    username = request.POST.get('user', '')
    password1 = request.POST.get('pwd', '')

    if len(username) <= 3:
        info = 'Username must be longer than 3 characters'
        result['msg'] = info
        return JsonResponse(result)

    if len(password1)<8 or len(password1)>20:
        info = 'Password length does not meet requirements, should be 8~20 characters.'
        result['msg'] = info
        return JsonResponse(result)

    user = UserProfile.objects.filter(Q(username=username)).first()
    if user:
        info = 'Username already exists.'
        result['msg'] = info
        return JsonResponse(result)
    user = UserProfile(
        username=username,
        password=make_password(password1),
        is_admin = True if UserProfile.objects.count()==0 else False,
        is_superuser = True if UserProfile.objects.count()==0 else False,
        is_active = True
    )
    user.save()
    result['msg'] = info
    result['code'] = 1
    return JsonResponse(result)

@login_required(login_url='/api/user_action?action=login')
def user_logout(request):
    # Handles user logout
    info = ''
    auth.logout(request)
    return HttpResponseRedirect('/api/user_action?action=login')
        
def get_single_info(uid):
    # Fetches single user information
    online_count = 0
    peers = RustDeskPeer.objects.filter(Q(uid=uid))
    rids = [x.rid for x in peers]
    peers = {x.rid:model_to_dict(x) for x in peers}
    devices = RustDesDevice.objects.filter(rid__in=rids)
    devices = {x.rid:x for x in devices}

    now = datetime.datetime.now()
    for rid, device in devices.items():
        peers[rid]['create_time'] = device.create_time.strftime('%Y-%m-%d')
        peers[rid]['update_time'] = device.update_time.strftime('%Y-%m-%d')
        peers[rid]['version'] = device.version
        peers[rid]['memory'] = device.memory
        peers[rid]['cpu'] = device.cpu
        peers[rid]['os'] = device.os
        peers[rid]['ip'] = device.ip
        if (now-device.update_time).seconds <=120:
            peers[rid]['status'] = 'Online'
            online_count += 1
        else:
            peers[rid]['status'] = 'X'

    for rid in peers.keys():
        peers[rid]['has_rhash'] = 'Yes' if len(peers[rid]['rhash'])>1 else 'No'
        peers[rid]['status'] = 'X'

    sorted_peers = sorted(peers.items(), key=custom_sort, reverse=True)
    new_ordered_dict = {}
    for key, peer in sorted_peers:
        new_ordered_dict[key] = peer

    return ([v for k,v in new_ordered_dict.items()], online_count)

def get_all_info():
    # Fetches all device and peer information
    online_count = 0
    devices = RustDesDevice.objects.all()
    peers = RustDeskPeer.objects.all()
    devices = {x.rid:model_to_dict2(x) for x in devices}
    now = datetime.datetime.now()
    for peer in peers:
        user = UserProfile.objects.filter(Q(id=peer.uid)).first()
        device = devices.get(peer.rid, None)
        if device:
            devices[peer.rid]['rust_user'] = user.username

    for k, v in devices.items():
        if (now-datetime.datetime.strptime(v['update_time'], '%Y-%m-%d')).seconds <=120:
            devices[k]['status'] = 'Online'
            online_count += 1
        else: 
           devices[k]['status'] = 'X'

    sorted_devices = sorted(devices.items(), key=custom_sort, reverse=True)
    new_ordered_dict = {}
    for key, device in sorted_devices:
        new_ordered_dict[key] = device
    return ([v for k,v in new_ordered_dict.items()], online_count)

def custom_sort(item):
    status = item[1]['status']
    if status == 'Online':
        return 1
    else:
        return 0

@login_required(login_url='/api/user_action?action=login')
def work(request):
    # Main work view
    username = request.user
    u = UserProfile.objects.get(username=username)
    single_info, online_count_single = get_single_info(u.id)

    all_info, online_count_all = get_all_info()
    print(all_info)

    return render(request, 'show_work.html', {'single_info':single_info, 'all_info':all_info, 'u':u, 'online_count_single':online_count_single, 'online_count_all':online_count_all})

def check_sharelink_expired(sharelink):
    # Checks if a share link is expired
    now = datetime.datetime.now()
    if sharelink.create_time > now:
        return False
    if (now - sharelink.create_time).seconds <15 * 60:
        return False
    else:
        sharelink.is_expired = True
        sharelink.save()
        return True

@login_required(login_url='/api/user_action?action=login')
def share(request):
    # Share view for handling peer sharing and share link management
    peers = RustDeskPeer.objects.filter(Q(uid=request.user.id))
    sharelinks = ShareLink.objects.filter(Q(uid=request.user.id) & Q(is_used=False) & Q(is_expired=False))

    # Optimize resources: Handle expired requests, check for expiry on any request instead of running a cron job.
    now = datetime.datetime.now()
    for sl in sharelinks:
        check_sharelink_expired(sl)
    sharelinks = ShareLink.objects.filter(Q(uid=request.user.id) & Q(is_used=False) & Q(is_expired=False))
    peers = [{'id':ix+1, 'name':f'{p.rid}|{p.alias}'} for ix, p in enumerate(peers)]
    sharelinks = [{'shash':s.shash, 'is_used':s.is_used, 'is_expired':s.is_expired, 'create_time':s.create_time, 'peers':s.peers} for ix, s in enumerate(sharelinks)]

    if request.method == 'GET':
        url = request.build_absolute_uri()
        if url.endswith('share'):
            return render(request, 'share.html', {'peers':peers, 'sharelinks':sharelinks})
        else:
            shash = url.split('/')[-1]
            sharelink = ShareLink.objects.filter(Q(shash=shash))
            msg = ''
            title = 'Success'
            if not sharelink:
                title = 'Error'
                msg = f'Link {url}:<br>The share link does not exist or has expired.'
            else:
                sharelink = sharelink[0]
                if str(request.user.id) == str(sharelink.uid):
                    title = 'Error'
                    msg = f'Link {url}:<br><br>You can not share the link with yourself, can you ! '
                else:
                    sharelink.is_used = True
                    sharelink.save()
                    peers = sharelink.peers
                    peers = peers.split(',')
                    # Skip if one's own peers overlap
                    peers_self_ids = [x.rid for x in RustDeskPeer.objects.filter(Q(uid=request.user.id))]
                    peers_share = RustDeskPeer.objects.filter(Q(rid__in=peers) & Q(uid=sharelink.uid))
                    peers_share_ids = [x.rid for x in peers_share]

                    for peer in peers_share:
                        if peer.rid in peers_self_ids:
                            continue
                        
                        peer_f = RustDeskPeer.objects.filter(Q(rid=peer.rid) & Q(uid=sharelink.uid))
                        if not peer_f:
                            msg += f"{peer.rid} already exists,"
                            continue
                        
                        if len(peer_f) > 1:
                             msg += f'{peer.rid} has multiple instances, skipped. '
                             continue
                        peer = peer_f[0]
                        peer.id = None
                        peer.uid = request.user.id
                        peer.save()
                        msg += f"{peer.rid},"

                    msg += 'has been successfully acquired.'

            return render(request, 'msg.html', {'title':msg, 'msg':msg})
    else:
        data = request.POST.get('data', '[]')

        data = json.loads(data)
        if not data:
            return JsonResponse({'code':0, 'msg':'Data is empty.'})
        rustdesk_ids = [x['title'].split('|')[0] for x in data]
        rustdesk_ids = ','.join(rustdesk_ids)
        sharelink = ShareLink(
            uid=request.user.id,
            shash = getStrSha256(str(time.time())+settings.SALT_CRED),
            peers=rustdesk_ids,
        )
        sharelink.save()

        return JsonResponse({'code':1, 'shash':sharelink.shash})

@login_required(login_url='/api/user_action?action=login')
def installers(request):
    return render(request, 'installers.html')

def get_conn_log():
    logs = ConnLog.objects.all()
    logs = {x.id:model_to_dict(x) for x in logs}

    for k, v in logs.items():
        try:
            peer = RustDeskPeer.objects.get(rid=v['rid'])
            logs[k]['alias'] = peer.alias
        except:
            logs[k]['alias'] = 'UNKNOWN'
        try:
            peer = RustDeskPeer.objects.get(rid=v['from_id'])
            logs[k]['from_alias'] = peer.alias
        except:
            logs[k]['from_alias'] = 'UNKNOWN'
        #from_zone = tz.tzutc()
        #to_zone = tz.tzlocal()
        #utc = logs[k]['logged_at']
        #utc = utc.replace(tzinfo=from_zone)
        #logs[k]['logged_at'] = utc.astimezone(to_zone)
        try:
            duration = round((logs[k]['conn_end'] - logs[k]['conn_start']).total_seconds())
            m, s = divmod(duration, 60)
            h, m = divmod(m, 60)
            #d, h = divmod(h, 24)
            logs[k]['duration'] = f'{h:02d}:{m:02d}:{s:02d}'
        except:
            logs[k]['duration'] = -1

    sorted_logs = sorted(logs.items(), key=lambda x: x[1]['conn_start'], reverse=True)
    new_ordered_dict = {}
    for key, alog in sorted_logs:
        new_ordered_dict[key] = alog

    return [v for k, v in new_ordered_dict.items()]

def get_file_log():
    logs = FileLog.objects.all()
    logs = {x.id:model_to_dict(x) for x in logs}

    for k, v in logs.items():
        try:
            peer_remote = RustDeskPeer.objects.get(rid=v['remote_id'])
            logs[k]['remote_alias'] = peer_remote.alias
        except:
            logs[k]['remote_alias'] = 'UNKNOWN'
        try:
            peer_user = RustDeskPeer.objects.get(rid=v['user_id'])
            logs[k]['user_alias'] = peer_user.alias
        except:
            logs[k]['user_alias'] = 'UNKNOWN'

    sorted_logs = sorted(logs.items(), key=lambda x: x[1]['logged_at'], reverse=True)
    new_ordered_dict = {}
    for key, alog in sorted_logs:
        new_ordered_dict[key] = alog

    return [v for k, v in new_ordered_dict.items()]

@login_required(login_url='/api/user_action?action=login')
def conn_log(request):
    paginator = Paginator(get_conn_log(), 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'show_conn_log.html', {'page_obj':page_obj})

@login_required(login_url='/api/user_action?action=login')
def file_log(request):
    paginator = Paginator(get_file_log(), 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'show_file_log.html', {'page_obj':page_obj})

@login_required(login_url='/api/user_action?action=login')
def add_peer(request):
    if request.method == 'POST':
        form = AddPeerForm(request.POST)
        if form.is_valid():
            rid = form.cleaned_data['clientID']
            uid = request.user.id
            username = form.cleaned_data['username']
            hostname = form.cleaned_data['hostname']
            plat = form.cleaned_data['platform']
            alias = form.cleaned_data['alias']
            tags = form.cleaned_data['tags']
            ip = form.cleaned_data['ip']

            peer = RustDeskPeer(
                uid = uid,
                rid = rid,
                username = username,
                hostname = hostname,
                platform = plat,
                alias = alias,
                tags = tags,
                ip = ip
            )
            peer.save()
            return HttpResponseRedirect('/api/work')
    else:
        rid = request.GET.get('rid','')
        form = AddPeerForm()
    return render(request, 'add_peer.html', {'form': form, 'rid': rid})

@login_required(login_url='/api/user_action?action=login')
def edit_peer(request):
    if request.method == 'POST':
        form = EditPeerForm(request.POST)
        if form.is_valid():
            rid = form.cleaned_data['clientID']
            uid = request.user.id
            username = form.cleaned_data['username']
            hostname = form.cleaned_data['hostname']
            plat = form.cleaned_data['platform']
            alias = form.cleaned_data['alias']
            tags = form.cleaned_data['tags']

            updated_peer = RustDeskPeer.objects.get(rid=rid,uid=uid)
            updated_peer.username=username
            updated_peer.hostname=hostname
            updated_peer.platform=plat
            updated_peer.alias=alias
            updated_peer.tags=tags
            updated_peer.save()

            return HttpResponseRedirect('/api/work')
        else:
            print(form.errors)
    else:
        rid = request.GET.get('rid','')
        peer = RustDeskPeer.objects.get(rid=rid)
        initial_data = {
            'clientID': rid,
            'alias': peer.alias,
            'tags': peer.tags,
            'username': peer.username,
            'hostname': peer.hostname,
            'platform': peer.platform,
            'ip': peer.ip
        }
        form = EditPeerForm(initial=initial_data)
        return render(request, 'edit_peer.html', {'form': form, 'peer': peer})
    
@login_required(login_url='/api/user_action?action=login')
def assign_peer(request):
    if request.method == 'POST':
        form = AssignPeerForm(request.POST)
        if form.is_valid():
            rid = form.cleaned_data['clientID']
            uid = form.cleaned_data['uid']
            username = form.cleaned_data['username']
            hostname = form.cleaned_data['hostname']
            plat = form.cleaned_data['platform']
            alias = form.cleaned_data['alias']
            tags = form.cleaned_data['tags']
            ip = form.cleaned_data['ip']

            peer = RustDeskPeer(
                uid = uid.id,
                rid = rid,
                username = username,
                hostname = hostname,
                platform = plat,
                alias = alias,
                tags = tags,
                ip = ip
            )
            peer.save()
            return HttpResponseRedirect('/api/work')
        else:
            print(form.errors)
    else:
        rid = request.GET.get('rid')
        form = AssignPeerForm()
        #get list of users from the database
        return render(request, 'assign_peer.html', {'form':form, 'rid': rid})
    
@login_required(login_url='/api/user_action?action=login')
def delete_peer(request):
    rid = request.GET.get('rid')
    peer = RustDeskPeer.objects.filter(Q(uid=request.user.id) & Q(rid=rid))
    peer.delete()
    return HttpResponseRedirect('/api/work')

# --- 2FA Views ---

def _generate_recovery_codes():
    """Generates a list of unique, random recovery codes."""
    codes = []
    for _ in range(NUMBER_OF_RECOVERY_CODES):
        codes.append(os.urandom(RECOVERY_CODE_LENGTH // 2).hex()) # Each byte becomes 2 hex chars
    return codes

def _hash_recovery_code(code):
    """Hashes a single recovery code."""
    return hashlib.sha256(code.encode()).hexdigest()

def _store_recovery_codes(user, plain_codes):
    """Hashes and stores recovery codes for the user."""
    hashed_codes = [_hash_recovery_code(code) for code in plain_codes]
    user.otp_recovery_codes = json.dumps(hashed_codes) # Store as a JSON array of strings
    # user.save() should be called after this by the calling function

@login_required(login_url='/api/user_action?action=login')
def setup_2fa(request):
    user = request.user
    if user.is_2fa_enabled:
        # Optionally, redirect to a page informing that 2FA is already enabled
        # or to a management page for 2FA.
        # For now, just redirect to work or show a message.
        # return HttpResponseRedirect('/api/work')
        # For simplicity, let's render a message, or ideally, redirect to a 2FA management page
        return render(request, 'msg.html', {'title': '2FA Error', 'msg': 'Two-Factor Authentication is already enabled for your account.'})

    if request.method == 'GET':
        # Generate a new secret key for the user
        otp_secret_key = pyotp.random_base32()
        request.session['otp_secret_key_setup'] = otp_secret_key # Store in session temporarily

        totp = pyotp.TOTP(otp_secret_key)
        provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name=OTP_ISSUER_NAME)

        # Generate QR code
        img = qrcode.make(provisioning_uri)
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()

        return render(request, 'setup_2fa.html', {
            'qr_code_base64': qr_code_base64,
            'otp_secret_key': otp_secret_key # Display this to the user as an alternative to QR
        })

    elif request.method == 'POST': # This will be the confirmation step
        otp_code = request.POST.get('otp_code', '').strip()
        otp_secret_key_from_session = request.session.get('otp_secret_key_setup')

        if not otp_secret_key_from_session:
            return render(request, 'msg.html', {'title': 'Error', 'msg': 'Session expired or invalid. Please try setting up 2FA again.'})

        if not otp_code:
            # Need to regenerate QR for the template if we show an error on the same page
            totp_temp = pyotp.TOTP(otp_secret_key_from_session)
            provisioning_uri_temp = totp_temp.provisioning_uri(name=user.username, issuer_name=OTP_ISSUER_NAME)
            img_temp = qrcode.make(provisioning_uri_temp)
            buffered_temp = io.BytesIO()
            img_temp.save(buffered_temp, format="PNG")
            qr_code_base64_temp = base64.b64encode(buffered_temp.getvalue()).decode()
            return render(request, 'setup_2fa.html', {
                'qr_code_base64': qr_code_base64_temp,
                'otp_secret_key': otp_secret_key_from_session,
                'error': 'OTP code is required.'
            })

        totp = pyotp.TOTP(otp_secret_key_from_session)
        if totp.verify(otp_code):
            # OTP is valid, finalize 2FA setup
            user.otp_secret_key = otp_secret_key_from_session
            user.is_2fa_enabled = True

            plain_recovery_codes = _generate_recovery_codes()
            _store_recovery_codes(user, plain_recovery_codes)

            user.save()

            # Clear the temporary secret from session
            if 'otp_secret_key_setup' in request.session:
                del request.session['otp_secret_key_setup']

            # Display recovery codes to the user (they must save these)
            # It's better to have a dedicated template for this.
            # For now, passing them to a generic message template or a new one.
            return render(request, 'display_recovery_codes.html', {
                'title': '2FA Enabled Successfully!',
                'msg': 'Please save these recovery codes in a safe place. Each can be used once if you lose access to your authenticator app.',
                'recovery_codes': plain_recovery_codes
            })
        else:
            # OTP is invalid, show error
            # Regenerate QR for the template
            totp_temp = pyotp.TOTP(otp_secret_key_from_session)
            provisioning_uri_temp = totp_temp.provisioning_uri(name=user.username, issuer_name=OTP_ISSUER_NAME)
            img_temp = qrcode.make(provisioning_uri_temp)
            buffered_temp = io.BytesIO()
            img_temp.save(buffered_temp, format="PNG")
            qr_code_base64_temp = base64.b64encode(buffered_temp.getvalue()).decode()

            return render(request, 'setup_2fa.html', {
                'qr_code_base64': qr_code_base64_temp,
                'otp_secret_key': otp_secret_key_from_session,
                'error': 'Invalid OTP code. Please try again.'
            })
    else:
        # Should not happen if routes are set up for GET and POST only
        return render(request, 'msg.html', {'title': 'Error', 'msg': 'Invalid request method.'})

# Note: I've combined setup and confirm into one view `setup_2fa` that handles GET for setup and POST for confirmation.
# This is a common pattern. If you prefer separate views like `confirm_2fa` for POST, we can split it.
# For now, the plan step "Vista confirm_2fa (POST)" is handled by the POST part of the `setup_2fa` view.


def _verify_recovery_code(user, code_to_check):
    """
    Verifies a recovery code against the stored hashed codes.
    If valid, removes it from the list of available codes.
    Returns True if valid and consumed, False otherwise.
    """
    if not user.otp_recovery_codes:
        return False

    hashed_code_to_check = _hash_recovery_code(code_to_check)

    try:
        stored_hashed_codes = json.loads(user.otp_recovery_codes)
        if not isinstance(stored_hashed_codes, list):
            return False # Should be a list
    except json.JSONDecodeError:
        return False

    if hashed_code_to_check in stored_hashed_codes:
        stored_hashed_codes.remove(hashed_code_to_check)
        user.otp_recovery_codes = json.dumps(stored_hashed_codes)
        # user.save() will be called by the calling view after successful login
        return True
    return False

# No @login_required here, as the user is not fully logged in yet.
# We rely on a session variable to know which user is trying to log in.
def verify_otp_login(request):
    # Get user_id from session, placed there by the initial login view
    user_id_to_verify = request.session.get('2fa_user_id_to_verify')

    if not user_id_to_verify:
        # No user_id in session, perhaps session expired or direct access to this URL
        return render(request, 'msg.html', {'title': 'Login Error', 'msg': 'No pending 2FA verification. Please log in normally.'})

    try:
        user = UserProfile.objects.get(id=user_id_to_verify)
    except UserProfile.DoesNotExist:
        return render(request, 'msg.html', {'title': 'Login Error', 'msg': 'User not found for 2FA verification.'})

    if not user.is_2fa_enabled:
        # Should not happen if initial login view is correct, but as a safeguard:
        # Log them in directly if 2FA somehow got disabled between steps.
        auth.login(request, user)
        if '2fa_user_id_to_verify' in request.session:
            del request.session['2fa_user_id_to_verify']
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL if hasattr(settings, 'LOGIN_REDIRECT_URL') else '/api/work')

    # Pre-check for missing otp_secret_key if 2FA is enabled
    if not user.otp_secret_key:
        # This is an invalid state: 2FA is enabled, but no secret key is stored.
        # Log this issue for admin, and inform the user.
        # Consider using proper logging framework in a real application
        print(f"CRITICAL: User {user.username} (ID: {user.id}) has 2FA enabled but no otp_secret_key.")
        return render(request, 'msg.html', {
            'title': '2FA Configuration Error',
            'msg': 'Your Two-Factor Authentication setup is incomplete or corrupted. Please try disabling and re-enabling 2FA from your profile, or contact support if the issue persists.'
        })

    if request.method == 'POST':
        otp_code = request.POST.get('otp_code', '').strip()
        if not otp_code:
            return render(request, 'verify_otp_login.html', {'error': 'OTP code is required.'})

        # Now it's safer to call pyotp.TOTP() because we've checked user.otp_secret_key
        totp = pyotp.TOTP(user.otp_secret_key)
        if totp.verify(otp_code):
            # Standard OTP is valid
            auth.login(request, user) # Complete the login
            user.save() # To save any changes if a recovery code was used then standard OTP (though unlikely path)
            if '2fa_user_id_to_verify' in request.session:
                del request.session['2fa_user_id_to_verify']
            return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL if hasattr(settings, 'LOGIN_REDIRECT_URL') else '/api/work')
        elif _verify_recovery_code(user, otp_code):
            # Recovery code is valid and has been consumed
            auth.login(request, user) # Complete the login
            user.save() # Save the user model because recovery codes list has changed
            if '2fa_user_id_to_verify' in request.session:
                del request.session['2fa_user_id_to_verify']
            # Optionally, message user that a recovery code was used
            return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL if hasattr(settings, 'LOGIN_REDIRECT_URL') else '/api/work')
        else:
            # Both standard OTP and recovery code are invalid
            return render(request, 'verify_otp_login.html', {'error': 'Invalid OTP code or recovery code.'})

    # GET request
    return render(request, 'verify_otp_login.html')
