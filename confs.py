# -*- coding: utf-8 -*-

import datetime

BASE_DOMAIN = ''
LOCAL_IPV4 = ''
LOCAL_IPV6 = ''
SOA_MNAME=''
SOA_RNAME=''
SOA_SERIAL=int(datetime.datetime.now().strftime('%Y%m%d%S'))
NS_SERVERS=[]
ONLY_PRIVATE_IPS = False