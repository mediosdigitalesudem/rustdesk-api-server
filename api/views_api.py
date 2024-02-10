# cython:language_level=3
from django.http import JsonResponse
import json
import time
import datetime
import hashlib
from django.contrib import auth
from django.forms.models import model_to_dict
from api.models import RustDeskToken, UserProfile, RustDeskTag, RustDeskPeer, RustDesDevice
from django.db.models import Q
import copy
from .views_front import *
from django.conf import settings


def login(request):
    result = {}
    if request.method == 'GET':
        result['error'] = 'Wrong request method! Please use POST.'
        return JsonResponse(result)

    data = json.loads(request.body.decode())
    
    username = data.get('username', '')
    password = data.get('password', '')
    rid = data.get('id', '')
    uuid = data.get('uuid', '')
    autoLogin = data.get('autoLogin', True)
    rtype = data.get('type', '')
    deviceInfo = data.get('deviceInfo', '')
    user = auth.authenticate(username=username, password=password)
    if not user:
        result['error'] = 'Incorrect account or password! Please try again, multiple failed attempts will lock your IP!'
        return JsonResponse(result)
    user.rid = rid
    user.uuid = uuid
    user.autoLogin = autoLogin
    user.rtype = rtype
    user.deviceInfo = json.dumps(deviceInfo)
    user.save()
    
    token = RustDeskToken.objects.filter(Q(uid=user.id) & Q(username=user.username) & Q(rid=user.rid)).first()
    
    # Check if expired
    if token:
        now_t = datetime.datetime.now()
        nums = (now_t - token.create_time).seconds if now_t > token.create_time else 0
        if nums >= EFFECTIVE_SECONDS:
            token.delete()
            token = None
    
    if not token:
        # Get and save token
        token = RustDeskToken(
            username=user.username,
            uid=user.id,
            uuid=user.uuid,
            rid=user.rid,
            access_token=getStrSha256(str(time.time())+settings.SALT_CRED)
        )
        token.save()

    result['access_token'] = token.access_token
    result['type'] = 'access_token'
    result['user'] = {'name': user.username}
    return JsonResponse(result)


def logout(request):
    if request.method == 'GET':
        result = {'error':'Wrong request method!'}
        return JsonResponse(result)
    
    data = json.loads(request.body.decode())
    rid = data.get('id', '')
    uuid = data.get('uuid', '')
    user = UserProfile.objects.filter(Q(rid=rid) & Q(uuid=uuid)).first()
    if not user:
        result = {'error':'Abnormal request!'}
        return JsonResponse(result)
    token = RustDeskToken.objects.filter(Q(uid=user.id) & Q(rid=user.rid)).first()
    if token:
        token.delete()

    result = {'code':1}
    return JsonResponse(result)


def currentUser(request):
    result = {}
    if request.method == 'GET':
        result['error'] = 'Incorrect submission method!'
        return JsonResponse(result)
    postdata = json.loads(request.body)
    rid = postdata.get('id', '')
    uuid = postdata.get('uuid', '')
    
    access_token = request.META.get('HTTP_AUTHORIZATION', '')
    access_token = access_token.split('Bearer ')[-1]
    token = RustDeskToken.objects.filter(Q(access_token=access_token)).first()
    user = None
    if token:
        user = UserProfile.objects.filter(Q(id=token.uid)).first()
    
    if user:
        if token:
            result['access_token'] = token.access_token
        result['type'] = 'access_token'
        result['name'] = user.username
    return JsonResponse(result)


def ab(request):
    '''
    '''
    access_token = request.META.get('HTTP_AUTHORIZATION', '')
    access_token = access_token.split('Bearer ')[-1]
    token = RustDeskToken.objects.filter(Q(access_token=access_token)).first()
    if not token:
        result = {'error':'Error pulling the list!'}
        return JsonResponse(result)
    
    if request.method == 'GET':
        result = {}
        uid = token.uid
        tags = RustDeskTag.objects.filter(Q(uid=uid))
        tag_names = []
        tag_colors = {}
        if tags:
            tag_names = [str(x.tag_name) for x in tags]
            tag_colors = {str(x.tag_name):int(x.tag_color) for x in tags if x.tag_color!=''}
        
        peers_result = []
        peers = RustDeskPeer.objects.filter(Q(uid=uid))
        if peers:
            for peer in peers:
                tmp = {
                    'id': peer.rid,
                    'username': peer.username,
                    'hostname': peer.hostname,
                    'alias': peer.alias,
                    'platform': peer.platform,
                    'tags': peer.tags.split(','),
                    'hash': peer.rhash,
                }
                peers_result.append(tmp)
        
        result['updated_at'] = datetime.datetime.now()
        result['data'] = {
            'tags': tag_names,
            'peers': peers_result,
            'tag_colors': json.dumps(tag_colors)
        }
        result['data'] = json.dumps(result['data'])
        return JsonResponse(result)
    else:
        postdata = json.loads(request.body.decode())
        data = postdata.get('data', '')
        data = {} if data == '' else json.loads(data)
        tagnames = data.get('tags', [])
        tag_colors = data.get('tag_colors', '')
        tag_colors = {} if tag_colors == '' else json.loads(tag_colors)
        peers = data.get('peers', [])
        
        if tagnames:
            # Delete old tags
            RustDeskTag.objects.filter(uid=token.uid).delete()
            # Add new ones
            newlist = []
            for name in tagnames:
                tag = RustDeskTag(
                    uid=token.uid,
                    tag_name=name,
                    tag_color=tag_colors.get(name, '')
                )
                newlist.append(tag)
            RustDeskTag.objects.bulk_create(newlist)
        if peers:
            RustDeskPeer.objects.filter(uid=token.uid).delete()
            newlist = []
            for one in peers:
                peer = RustDeskPeer(
                    uid=token.uid,
                    rid=one['id'],
                    username=one['username'],
                    hostname=one['hostname'],
                    alias=one['alias'],
                    platform=one['platform'],
                    tags=','.join(one['tags']),
                    rhash=one['hash'],                  
                )
                newlist.append(peer)
            RustDeskPeer.objects.bulk_create(newlist)

    result = {
    'code':102,
    'data':'Error updating the address book'
    }
    return JsonResponse(result)

def sysinfo(request):
    # Device information is sent only after client registration
    result = {}
    if request.method == 'GET':
        result['error'] = 'Incorrect submission method!'
        return JsonResponse(result)
    
    postdata = json.loads(request.body)
    device = RustDesDevice.objects.filter(Q(rid=postdata['id']) & Q(uuid=postdata['uuid'])).first()
    if not device:
        device = RustDesDevice(
            rid=postdata['id'],
            cpu=postdata['cpu'],
            hostname=postdata['hostname'],
            memory=postdata['memory'],
            os=postdata['os'],
            username=postdata.get('username', '-'),
            uuid=postdata['uuid'],
            version=postdata['version'],
        )
        device.save()
    else:
        postdata2 = copy.copy(postdata)
        postdata2['rid'] = postdata2['id']
        postdata2.pop('id')
        RustDesDevice.objects.filter(Q(rid=postdata['id']) & Q(uuid=postdata['uuid'])).update(**postdata2)
    result['data'] = 'ok'
    return JsonResponse(result)

def heartbeat(request):
    postdata = json.loads(request.body)
    device = RustDesDevice.objects.filter(Q(rid=postdata['id']) & Q(uuid=postdata['uuid'])).first()
    if device:
        device.save()
    # Token keep-alive
    create_time = datetime.datetime.now() + datetime.timedelta(seconds=EFFECTIVE_SECONDS)
    RustDeskToken.objects.filter(Q(rid=postdata['id']) & Q(uuid=postdata['uuid'])).update(create_time=create_time)
    result = {}
    result['data'] = 'Online'
    return JsonResponse(result)
    
def users(request):
    result = {
    'code':1,
    'data':'Alright'
    }
    return JsonResponse(result)
    
def peers(request):
    result = {
    'code':1,
    'data':'ok'
    }
    return JsonResponse(result)
