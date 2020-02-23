# Copyright (c) 2012-2016 Seafile Ltd.

from django.conf.urls import url
from seahub.dingtalk.views import dingtalk_login, dingtalk_callback, \
        dingtalk_connect, dingtalk_connect_callback, dingtalk_disconnect
urlpatterns = [
    url(r'login/$', dingtalk_login, name='dingtalk_login'),
    url(r'callback/$', dingtalk_callback, name='dingtalk_callback'),
    url(r'connect/$', dingtalk_connect, name='dingtalk_connect'),
    url(r'connect-callback/$', dingtalk_connect_callback, name='dingtalk_connect_callback'),
    url(r'disconnect/$', dingtalk_disconnect, name='dingtalk_disconnect'),
]
