# -*- coding: utf-8 -*-
import os
import sys
from django.core.wsgi import get_wsgi_application
from django.db import models
from django.apps import apps
if __name__ == '__main__':
     print("Starting environment setting script...")
     os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'GSM.settings')
     application = get_wsgi_application()
     from django.db import models
     from django.apps import apps
     import json
     import simplejson
     from decimal import Decimal
     from json import loads
     from django.core import serializers
     import re
     from django.db import connection
     import pdb
     import gsm_utility.models as um
     from django.forms.models import model_to_dict
     from GSM.views import GSMView
     cursor = connection.cursor(#pdb.set_trace()()
     print("Hello")
     f_obj = um.Feedback.objects.filter(pk=1)
     print(f_obj)
     testv2 = map(lambda x: x.get('fields'),json.loads(serializers.serialize('json',um.Feedback.objects.all())))
     print(testv2)
