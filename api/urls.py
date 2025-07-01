import django
if django.__version__.split('.')[0]>='4':
    from django.urls import re_path as url
else:
    from django.conf.urls import  url, include

from api import views
 
urlpatterns = [
    url(r'^login',views.login),
    url(r'^logout',views.logout),
    url(r'^ab',views.ab),
    url(r'^users',views.users),
    url(r'^peers',views.peers),
    url(r'^currentUser',views.currentUser),
    url(r'^sysinfo',views.sysinfo),
    url(r'^heartbeat',views.heartbeat),
    #url(r'^register',views.register), 
    url(r'^user_action',views.user_action),  # 前端
    url(r'^work',views.work),  # 前端
    url(r'^share',views.share),  # 前端
    url(r'^installers',views.installers),  # 前端
    url(r'^conn_log',views.conn_log),
    url(r'^file_log',views.file_log),
    url(r'^audit',views.audit),
    url(r'^add_peer',views.add_peer),
    url(r'^delete_peer',views.delete_peer),
    url(r'^edit_peer',views.edit_peer),
    url(r'^assign_peer',views.assign_peer),
    # 2FA URLs
    url(r'^setup_2fa', views.setup_2fa, name='setup_2fa'), # Handles GET for showing QR/form and POST for OTP confirmation
    ]
