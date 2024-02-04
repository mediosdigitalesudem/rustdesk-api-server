# cython:language_level=3
from django.db import models
from django.contrib import admin


class RustDeskToken(models.Model):
    ''' Token
    '''
    username = models.CharField(verbose_name='Username', max_length=20)
    rid = models.CharField(verbose_name='RustDesk ID', max_length=16)
    uid = models.CharField(verbose_name='User ID', max_length=16)
    uuid = models.CharField(verbose_name='uuid', max_length=60)
    access_token = models.CharField(verbose_name='access_token', max_length=60, blank=True)
    create_time = models.DateTimeField(verbose_name='Login Time', auto_now_add=True)
    #expire_time = models.DateTimeField(verbose_name='Expiration Time')
    class Meta:
        ordering = ('-username',)
        verbose_name = "Token"
        verbose_name_plural = "Token List" 

class RustDeskTokenAdmin(admin.ModelAdmin):
    list_display = ('username', 'uid')
    search_fields = ('username', 'uid')
    list_filter = ('create_time', ) # Filter
    

class RustDeskTag(models.Model):
    ''' Tags
    '''
    uid = models.CharField(verbose_name='Owner User ID', max_length=16)
    tag_name = models.CharField(verbose_name='Tag Name', max_length=60)
    tag_color = models.CharField(verbose_name='Tag Color', max_length=60, blank=True)
    
    class Meta:
        ordering = ('-uid',)
        verbose_name = "Tags"
        verbose_name_plural = "Tags List"

class RustDeskTagAdmin(admin.ModelAdmin):
    list_display = ('tag_name', 'uid', 'tag_color')
    search_fields = ('tag_name', 'uid')
    list_filter = ('uid', )
    

class RustDeskPeer(models.Model):
    ''' Peers
    '''
    uid = models.CharField(verbose_name='User ID', max_length=16)
    rid = models.CharField(verbose_name='Client ID', max_length=60)
    username = models.CharField(verbose_name='System Username', max_length=20)
    hostname = models.CharField(verbose_name='Operating System Name', max_length=30)
    alias = models.CharField(verbose_name='Alias', max_length=30)
    platform = models.CharField(verbose_name='Platform', max_length=30)
    tags = models.CharField(verbose_name='Tags', max_length=30)
    rhash = models.CharField(verbose_name='Device Link Password', max_length=60)
    
    class Meta:
        ordering = ('-username',)
        verbose_name = "Peers"
        verbose_name_plural = "Peers List" 
        

class RustDeskPeerAdmin(admin.ModelAdmin):
    list_display = ('rid', 'uid', 'username', 'hostname', 'platform', 'alias', 'tags')
    search_fields = ('deviceid', 'alias')
    list_filter = ('rid', 'uid', )
    
    
class RustDesDevice(models.Model):
    rid = models.CharField(verbose_name='Client ID', max_length=60, blank=True)
    cpu = models.CharField(verbose_name='CPU', max_length=20)
    hostname = models.CharField(verbose_name='Hostname', max_length=20)
    memory = models.CharField(verbose_name='Memory', max_length=20)
    os = models.CharField(verbose_name='Operating System', max_length=20)
    uuid = models.CharField(verbose_name='uuid', max_length=60)
    username = models.CharField(verbose_name='System Username', max_length=60, blank=True)
    version = models.CharField(verbose_name='Client Version', max_length=20)
    create_time = models.DateTimeField(verbose_name='Device Registration Time', auto_now_add=True)
    update_time = models.DateTimeField(verbose_name='Device Update Time', auto_now=True, blank=True)
    
    class Meta:
        ordering = ('-rid',)
        verbose_name = "Device"
        verbose_name_plural = "Device List" 
    
class RustDesDeviceAdmin(admin.ModelAdmin):
    list_display = ('rid', 'hostname', 'memory', 'uuid', 'version', 'create_time', 'update_time')
    search_fields = ('hostname', 'memory')
    list_filter = ('rid', )



class ShareLink(models.Model):
    ''' Share Link
    '''
    uid = models.CharField(verbose_name='User ID', max_length=16)
    shash = models.CharField(verbose_name='Link Key', max_length=60)
    peers = models.CharField(verbose_name='Machine ID List', max_length=20)
    is_used = models.BooleanField(verbose_name='Used', default=False)
    is_expired = models.BooleanField(verbose_name='Expired', default=False)
    create_time = models.DateTimeField(verbose_name='Generation Time', auto_now_add=True)
    

    
    class Meta:
        ordering = ('-create_time',)
        verbose_name = "Share Link"
        verbose_name_plural = "Link List" 
        

class ShareLinkAdmin(admin.ModelAdmin):
    list_display = ('shash', 'uid', 'peers', 'is_used', 'is_expired', 'create_time')
    search_fields = ('peers', )
    list_filter = ('is_used', 'uid', 'is_expired' )
