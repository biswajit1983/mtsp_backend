# -*- coding: utf-8 -*-
import inspect
from enum import Enum
# import GSM.utility.models as um
import datetime
import time
import json
from django.contrib import messages
from django.shortcuts import render, render_to_response
from django.http import HttpResponse,HttpRequest,HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
# import gsm_utility.models as um
#from django.template.loader import get_template
import sendgrid
# from sendgrid import SendGridClientError
# from sendgrid import SendGridError, SendGridClientError, SendGridServerError
#from whatever.models import Recipient, Message
# import flyrobe_procurement.settings as fs
from django.template import Context, Template, loader
from django.utils import six
from django.apps import apps
from django.forms.models import model_to_dict
import pdb
import requests
import re
from Crypto.Cipher import AES
from Crypto.Hash import MD5, SHA256, SHA512
import base64
from django.conf import settings
import httplib2
import urllib
import datetime
import dateutil.parser
from pytz import timezone
from django.utils.timezone import utc
import random, csv, string
from decimal import Decimal
# from .serializers import *
# from rest_framework.renderers import JSONRenderer
# from rest_framework.parsers import JSONParser

whitehost_list = settings.WHITEHOSTS_LIST
whitedomain_list = settings.WHITEDOMAINS_LIST

class ChoiceEnum(Enum):
    @classmethod
    def choices(cls):
        # members = inspect.getmembers(cls, lambda m: not(inspect.isroutine(m)))
        # props = [m for m in members if not(m[0][:2] == '__')]
        # return tuple([(x[1], x[0]) for x in props])
        # return choices
        # pdb.set_trace()
        return [(e.name, e.value) for e in cls]
        return choices

    @classmethod
    def choices_dict(cls):
        return dict(cls.choices())

    @classmethod
    def reverse_dict(cls):
        # m_list = [(v.value,re.split('\.',str(v))[1]) for v in c_enum]
        # m_dict=dict(m_list)
        c_enum = cls.choices_dict()
        return dict((v,k) for k,v in c_enum.items())


def reverse_dict(ChoiceEnum):
    c_enum = ChoiceEnum
    m_list = [(v.value,re.split('\.',str(v))[1]) for v in c_enum]
    m_dict=dict(m_list)
    return m_dict

def pluck(*args):
    source = args[0]
    target_keys = args[1]
    target = {key:value for key,value in source.items() if key in target_keys}
    return target

def omit(*args):
    source = args[0].copy()
    target_keys = args[1]
    map(lambda i:source.pop(i,None),target_keys)
    return source


class EmailSendingUtil(object):
    def __init__(self,**kwargs):
        # pdb.set_trace()
        # print "Hello token utils"
        setattr(self,'data',{})
        for key, value in kwargs.items():
            setattr(self, key, value)
        personalization = {}
        from_obj = {}
        content = {}
        if hasattr(self,'to'):
            personalization['to'] = [{'email':email} for email in self.to]
        else:
            raise AttributeError("Receiver's email address not found...To attribute is missing")
        if hasattr(self,'cc'):
            personalization['cc'] = [{'email':email} for email in self.cc]
        if hasattr(self,'bcc'):
            personalization['bcc'] = [{'email':email} for email in self.bcc]
        if hasattr(self,'subject'):
            personalization['subject'] = self.subject
        if hasattr(self,'from_email'):
            from_obj['email'] = self.from_email
        else:
            raise AttributeError("Sender's email address not found...From attribute is missing")
        if hasattr(self,'template_path'):
            loaded_template = loader.get_template(self.template_path)
            content['type'] = "text/html"
        if hasattr(self,'email_context'):
            loaded_template=loaded_template.render(self.email_context)
        content['value'] = loaded_template
        self.data['personalizations'] = [personalization]
        self.data['from'] = from_obj
        self.data['content']=[content]
        self.sgrid = sendgrid.SendGridAPIClient(apikey=settings.API_KEYS['sendgrid']['key'])

    def send(self):
        #pdb.set_trace()()
        try:
            response = self.sgrid.client.mail.send.post(request_body=self.data)
            print(response.status_code)
            response_sendgrid = {}
            response_sendgrid['status']=response.status_code
            response_sendgrid['response']=response.body
            response_sendgrid['success']=True if response.status_code==202 else False
            return response_sendgrid
        except Exception as e:
            print(e)
            response_sendgrid = {}
            response_sendgrid['error']=str(e)
            return response_sendgrid


class GSMUsersUtils(object):
    def __init__(self,**kwargs):
        setattr(self,'model_name','GSMUsers')
        setattr(self,'app_label','gsm_utility')
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.model = apps.get_model(app_label=self.app_label,model_name=self.model_name)
        if hasattr(self,'params') and 'email' in self.params:
            try:
                params_fields = [k for k,v in self.params.items()]
                setattr(self,'params_fields',params_fields)
                self.user = self.model.objects.get(email=self.params['email'])
                fields = [k for k,v in model_to_dict(self.user).items() if not v=='']
                setattr(self,'original_fields',fields)
            except Exception as e:
                print(str(e))
                pass
        else:
            raise AttributeError("any of email or params attribute is missing in given parameters")

    def findOrCreate(self):
        # pdb.set_trace()
        if hasattr(self,'user'):
            if not set(self.params_fields).issubset(self.original_fields):
                # diff_list = list(set(self.params_fields).symmetric_difference(set(self.original_fields)))
                diff_list = list(set(self.params_fields)-(set(self.original_fields)))
                for k in diff_list:
                    if hasattr(self.user,k):
                        setattr(self.user,k,self.params[k])
                    else:
                        raise AttributeError("%s is unknow initial parameter"%(k))
                self.user.save(update_fields=diff_list)
            else:
                pass
        else:
            try:
                user_obj = self.model(**self.params)
                user_obj.save()
                # user_obj.save(update_fields=self.params_fields)
                setattr(self,'user',user_obj)
            except Exception as e:
                raise
        return self.user

    def findAndUpdate(self,**kwargs):
        if hasattr(self,'user'):
            for k,v in kwargs.items():
                if hasattr(self.user,k):
                    setattr(self.user,k,v)
                else:
                    raise AttributeError("%s is unknow update parameter"%(k))
            self.user.save(update_fields=kwargs.keys())
        else:
            raise ValueError("object does not exists to update. first create one to update")
        return self.user



# def email_sender(*args):
#     # pdb.set_trace()
#     #print args,kwargs
#     # pdb.set_trace()
#     welcome_mail_template = "utility/welcome.html"
#     user_info = args[0]
#     email_context = {'first_name':user_info['first_name']}
#     loaded_template = loader.get_template(welcome_mail_template).render(email_context)
#     # send_to_sendgrid = loaded_template.render(Context(email_context))
#     # api_key = settings.API_KEYS['sendgrid']['key']
#     sg = sendgrid.SendGridAPIClient(apikey=settings.API_KEYS['sendgrid']['key'])
#     data = {
#       "personalizations": [
#         {
#           "to": [
#             {
#               "email": "hidemi@globalsystemsmanagement.net"
#             }
#           ],
#           "cc": [
#           {
#             "email":"dream@cloudsmiths.io"
#           },
#           {
#             "email":"biswajit1983@gmail.com"
#           }
#           ],
#           "subject": "Welcome Mail From GSM"
#         }
#       ],
#       "from": {
#         "email": user_info['email']
#         # "email": "hidemi@globalsystemsmanagement.net"
#       },
#       "content": [
#         {
#           "type": "text/html",
#           "value": loaded_template
#         }
#       ]
#     }
#     try:
#         response = sg.client.mail.send.post(request_body=data)
#         print(response.status_code)
#     except Exception as e:
#         print(e)
#     return response.status_code,response.body

def original_set_response_header(**kwargs):
    pattern=re.compile("^chrome-extension://*")
    kwargs['badResponse']['success']=False
    if isinstance(kwargs['request'],HttpRequest) and isinstance(kwargs['response'],HttpResponse):
        kwargs['response']['success']=True
        kwargs['response']['Access-Control-Allow-Headers']="Content-Type, sessiontoken"
        if 'HTTP_ORIGIN' in kwargs['request'].META and kwargs['request'].META['HTTP_ORIGIN'] in whitedomain_list:
            kwargs['response']['Access-Control-Allow-Credentials']='true'
            kwargs['response']['Access-Control-Allow-Methods']="*"
            kwargs['response']['Access-Control-Allow-Origin']=kwargs['request'].META['HTTP_ORIGIN']
            kwargs['badResponse']['Access-Control-Allow-Origin']=kwargs['request'].META['HTTP_ORIGIN']
            # kwargs['response']['Access-Control-Allow-Origin']="*"
            #kwargs['response']['Access-Control-Allow-Origin']="http://web-staging.flyrobeapp.com/, http://localhost:8000/"
            kwargs['response']['Access-Control-Max-Age']="1728000"
            kwargs['response']['Cache-Control']="max-age=0, private, must-revalidate"
            kwargs['response'].__delitem__("X-Frame-Options")
            return True,kwargs['response'],kwargs['badResponse']
        elif 'HTTP_ORIGIN' in kwargs['request'].META and pattern.match(kwargs['request'].META['HTTP_ORIGIN']):
            kwargs['response']['Access-Control-Allow-Credentials']='true'
            kwargs['response']['Access-Control-Allow-Methods']="*"
            kwargs['response']['Access-Control-Allow-Origin']=kwargs['request'].META['HTTP_ORIGIN']
            kwargs['badResponse']['Access-Control-Allow-Origin']=kwargs['request'].META['HTTP_ORIGIN']
            #kwargs['response']['Access-Control-Allow-Origin']="http://web-staging.flyrobeapp.com/, http://localhost:8000/"
            kwargs['response']['Access-Control-Max-Age']="1728000"
            kwargs['response']['Cache-Control']="max-age=0, private, must-revalidate"
            kwargs['response'].__delitem__("X-Frame-Options")
            return True,kwargs['response'],kwargs['badResponse']
        elif 'HTTP_HOST' in kwargs['request'].META and kwargs['request'].META['HTTP_HOST'] in whitehost_list:
            kwargs['response']['Access-Control-Allow-Credentials']='true'
            kwargs['response']['Access-Control-Allow-Methods']="*"
            kwargs['response']['Access-Control-Allow-Origin']=kwargs['request'].META['HTTP_HOST']
            kwargs['badResponse']['Access-Control-Allow-Origin']=kwargs['request'].META['HTTP_HOST']
            #kwargs['response']['Access-Control-Allow-Origin']="http://web-staging.flyrobeapp.com/, http://localhost:8000/"
            kwargs['response']['Access-Control-Max-Age']="1728000"
            kwargs['response']['Cache-Control']="max-age=0, private, must-revalidate"
            kwargs['response'].__delitem__("X-Frame-Options")
            return True,kwargs['response'],kwargs['badResponse']
        elif not 'HTTP_ORIGIN' in kwargs['request'].META and 'HTTP_HOST' not in kwargs['request'].META:
            return True,kwargs['response'],kwargs['badResponse']
    else:
        return False,kwargs['response'],kwargs['badResponse']

def original_session_token_required(**kwargs):
    # request = kwargs['request'#pdb.set_trace()()
    # kwargs['response']['success']=True
    # kwargs['badResponse']['success']=False
    # pdb.set_trace()
    if 'HTTP_SESSIONTOKEN' in kwargs['request'].META:
        session_token = kwargs['request'].META['HTTP_SESSIONTOKEN']
        try:
            stoken = SessionTokenUtils(session_token=session_token)
        except Exception as e:
            message = str(e)
            kwargs['badResponse'].write("%s"%(json.dumps({"Message":"System generated::%s"%message})))
            return kwargs['request'],False,kwargs['response'],kwargs['badResponse']
        if not stoken.isValid():
            stoken.expireToken()
            kwargs['badResponse'].write("%s"%(json.dumps({"Message":"Session Token already expired!!!...Try with a new one"})))
            return kwargs['request'],False,kwargs['response'],kwargs['badResponse']
        else:
            try:
                kwargs['request'].META['HTTP_AUTHENTICATED_USER'] = stoken.user_model.objects.filter(pk=stoken.token.gsm_user.id)[0]
                kwargs['request'].META['HTTP_SESSIONTOKEN']=stoken
            except Exception as e:
                kwargs['badResponse'].write("%s"%(json.dumps({"Message":"Unauthorized user assoicted with the given session token"})))
                return kwargs['request'],False,kwargs['response'],kwargs['badResponse']
            return kwargs['request'],True,kwargs['response'],kwargs['badResponse']
    else:
        kwargs['badResponse'].write("%s"%(json.dumps({"Message":"Session Token not present inside request header!!!"})))
        return kwargs['request'],False,kwargs['response'],kwargs['badResponse']



def get_time_difference(sessiontoken):
    # pdb.set_trace()
    # print('hello')
    # print('hello again')
    if hasattr(sessiontoken,'created_at'):
        now = datetime.datetime.utcnow().replace(tzinfo=utc)
        timediff = now - sessiontoken.created_at
        return int((timediff.total_seconds())*1000) #sending in milliseconds

# def get_timestamp():
#     now = datetime.datetime.now()
#     re

current_milli_time = lambda: int(round(time.time() * 1000))
timestamp = lambda t=datetime.datetime.now():int((t - datetime.datetime.utcfromtimestamp(0)).total_seconds()*1000)
random_string = lambda size, chars=string.ascii_lowercase + string.digits : ''.join(random.choice(chars) for _ in range(size))

def get_MD5_encryption(str=None):
    m = MD5.new()
    if str:
        m.update(str.encode("utf-8"))
    return m.hexdigest()

def get_SHA256_encryption(str=None):
    s = SHA256.new()
    if str:
        s.update(str.encode("utf-8"))
    return s.hexdigest()

class TokenUtils(object):

    def __init__(self,**kwargs):
        # pdb.set_trace()
        # print "Hello token utils"
        for key, value in kwargs.items():
            setattr(self, key, value)
        if hasattr(self,'model_name') and hasattr(self,'app_label'):
            self.model = apps.get_model(app_label=self.app_label,model_name=self.model_name)
            self.user_model = apps.get_model(app_label=self.app_label,model_name='GSMUsers')
            self.object_validation(**kwargs)
            if not hasattr(self,'token') and  not hasattr(self,self.token):
                raise AttributeError("Didn't find any token of %s type."%(self.model_name))
            else:
                pass
        else:
            raise AttributeError("%s() didn't receive one of the attributes of app_label,model_name and token_obj."%(self.__class__.__name__))

    def object_validation(self,**kwargs):
        # pdb.set_trace()
        if 'id' in kwargs:
            try:
                self.token = self.model.objects.get(id=kwargs['id'],valid=True)
            except Exception as e:
                print(str(e))
                raise
        elif 'pk' in kwargs:
            try:
                self.token = self.model.objects.get(pk=kwargs['pk'],valid=True)
            except Exception as e:
                print(str(e))
                raise
        # elif 'token' in kwargs:
        #     try:
        #         self.token = self.model.objects.get(token=kwargs['token'],valid=True)
        #     except Exception as e:
        #         print(str(e))
        #         raise
        elif self.token_name in kwargs:
            if self.token_name == "session_token":
                try:
                    self.token = self.model.objects.get(session_token=kwargs[self.token_name],valid=True)
                except Exception as e:
                    print(str(e))
                    raise
            elif self.token_name == "verification_token":
                try:
                    self.token = self.model.objects.get(verification_token=kwargs[self.token_name],valid=True)
                except Exception as e:
                    print(str(e))
                    raise
            elif self.token_name == "password_token":
                try:
                    self.token = self.model.objects.get(password_token=kwargs[self.token_name],valid=True)
                except Exception as e:
                    print(str(e))
                    raise
            else:
                raise TypeError("No valid token name found inside passed arguments.")

        else:
            try:
                self.token = self.new(**kwargs)
            except Exception as e:
                print(str(e))
                raise

    def get_time_difference(self):
        if hasattr(self.token,'created_at'):
            now = datetime.datetime.utcnow().replace(tzinfo=utc)
            timediff = now - self.token.created_at
            return int((timediff.total_seconds())*1000)
        else:
            raise AttributeError("Didn't find created_at attributes in the given token of %s type."%(self.model_name))

    def isValid(self):
        return (self.get_time_difference() < self.TOKEN_EXPIRY_TIMES)


    def new(self,**kwargs):
        # pdb.set_trace()
        if hasattr(self,'token'):
            gsm_user_id = self.token.gsm_user.id
        elif all (k in kwargs for k in ("gsm_user",)):
            gsm_user_id = kwargs['gsm_user']
        else:
            raise AttributeError("Didn't find gsm_user attribute for creating token of %s type."%(self.model_name))
        flag = True
        try:
            gsm_usr_obj = self.user_model.objects.get(pk=gsm_user_id)
        except Exception as e:
            print(str(e))
            raise
        try:
            token = self.model.objects.get(gsm_user=gsm_usr_obj.id,valid=True)
            flag = False
        except Exception as e:
            if e.__class__.__name__ == "MultipleObjectsReturned":
                tokens = self.model.objects.all().values('id')
                for i in tokens:
                    t = self.model.objects.get(pk=i['id'])
                    t.vaild = False
                    t.save()

            elif e.__class__.__name__ == "DoesNotExist":
                pass
            else:
                flag = False
                raise
        if flag:
            if hasattr(self,'flag') and self.flag == 'skipNew':
                token=None
            else:
                new_token_obj = {'gsm_user':gsm_usr_obj,'valid':True,'salt':random_string(32),'valid_for':self.TOKEN_EXPIRY_TIMES}
                tmp_token = get_SHA256_encryption(new_token_obj['salt']+gsm_usr_obj.email)
                new_token_obj[self.token_name] = tmp_token
                token = self.model(**new_token_obj)
                token.save()
        return token

    def validateAndCreateNew(self):
        if not self.isValid():
            # self.token.valid = False
            # self.token.save()
            self.expireToken()
            self.token = self.new(gsm_user=self.token.gsm_user.id)
        return self.token.__dict__[self.token_name]

    def expireToken(self):
        if hasattr(self,'token'):
            self.token.valid = False
            self.token.save()
            # self.token = self.new(gsm_user=self.token.gsm_user)

            # new_token_obj['gsm_user'] = gsm_usr_obj


class VerificationTokenUtils(TokenUtils):
    def __init__(self,**kwargs):
        # import pdb#pdb.set_trace()()
        kwargs.update({'model_name':'VerificationToken','app_label':'gsm_utility', 'TOKEN_EXPIRY_TIMES' : settings.TOKEN_EXPIRY_TIMES['anyOtherToken'], 'token_name' : 'verification_token' })
        super(self.__class__,self).__init__(**kwargs)

    def alltokens(self):
        tokens = list(self.model.objects.all().values('id','verification_token','gsm_user','valid'))
        return tokens

    def send_mail(self,usr_obj):
        # res = {}
        if not usr_obj.mail_sent:
                try:
                    registration_verification_url = settings.URLS['registration_verification']+"?id="+str(usr_obj.id)+"&token="+self.token.__dict__[self.token_name]
                    email_sender = EmailSendingUtil(email_context={'first_name':usr_obj.first_name,'registration_verification_url':registration_verification_url},to=[usr_obj.email],cc=["biswajit1983@gmail.com"],subject="Registration verification mail from GSM",
                    from_email="hidemi@globalsystemsmanagement.net",template_path="utility/registration_verification_mail.html")
                    res = email_sender.send()
                    #change user's email_sent field too
                    usr_obj.mail_sent = True
                    usr_obj.save(update_fields=['mail_sent'])
                except Exception as e:
                    raise
        else:
            res = {"status": 202,"response": "","success": True}
        return res



class SessionTokenUtils(TokenUtils):
    def __init__(self,**kwargs):
        kwargs.update({'model_name':'SessionToken','app_label':'gsm_utility', 'TOKEN_EXPIRY_TIMES' : settings.TOKEN_EXPIRY_TIMES['sessionToken'], 'token_name' : 'session_token' })
        # TokenUtils.__init__(**kwargs)
        super(SessionTokenUtils,self).__init__(**kwargs)

    def alltokens(self):
        tokens = list(self.model.objects.all().values('id','session_token','gsm_user','valid'))
        return tokens

class PasswordTokenUtils(TokenUtils):
    def __init__(self,**kwargs):
        kwargs.update({'model_name':'PasswordToken','app_label':'gsm_utility', 'TOKEN_EXPIRY_TIMES' : settings.TOKEN_EXPIRY_TIMES['anyOtherToken'], 'token_name' : 'password_token' })
        # TokenUtils.__init__(**kwargs)
        super(PasswordTokenUtils,self).__init__(**kwargs)

    def alltokens(self):
        tokens = list(self.model.objects.all().values('id','password_token','gsm_user','valid'))
        return tokens

    def send_mail(self,usr_obj):
        # res = {}
        if not self.token.mail_sent:
                try:
                    change_password_url = settings.URLS['change_password']+"?id="+str(usr_obj.id)+"&token="+self.token.__dict__[self.token_name]
                    email_sender = EmailSendingUtil(email_context={'first_name':usr_obj.first_name,'change_password_url':change_password_url},to=[usr_obj.email],cc=["biswajit1983@gmail.com"],subject="Change password mail from GSM",
                    from_email="hidemi@globalsystemsmanagement.net",template_path="utility/change_password_mail.html")
                    res = email_sender.send()
                    self.token.mail_sent = True
                    self.token.save()
                    #change user's email_sent field too
                    # usr_obj.mail_sent = True
                    # usr_obj.save(update_fields=['mail_sent'])
                except Exception as e:
                    raise
        else:
            res = {"status": 202,"response": "","success": True}
        return res

    # def isValid(self):



#--------------------------Decorators--------------------------------#

def set_response_header(original_function):
    # pdb.set_trace()
    def new_function(request,*args,**kwargs):
        # print("I'm here!!!")
        status,response,badResponse = original_set_response_header(request=request,response=HttpResponse(content_type='application/json'),badResponse=HttpResponseBadRequest(content_type='application/json'))
        if not status:
            badResponse.write("%s"%(json.dumps({"Message":"Unauthorized request"})))
            return badResponse
            # return HttpResponseBadRequest(json.dumps({"Message":"Unauthorized request"}),content_type='application/json')
        return original_function(request,response,badResponse,*args,**kwargs)
    new_function.__doc__ = original_function.__doc__
    new_function.__name__ = original_function.__name__
    return new_function

def session_token_required(original_function):
    def new_function(request,response,badResponse,*args,**kwargs):
        request,status,response,badResponse = original_session_token_required(request=request,response=response,badResponse=badResponse)
        if not status:
            # badResponse.write("%s"%(json.dumps({"Message":"Unauthorized Session token"})))
            return badResponse
            # return HttpResponseBadRequest(json.dumps({"Message":"Unauthorized request"}),content_type='application/json')
        return original_function(request,response,badResponse,*args,**kwargs)
    new_function.__doc__ = original_function.__doc__
    new_function.__name__ = original_function.__name__
    return new_function

def convert(data):
    if isinstance(data, Decimal):    return float(data)
    if isinstance(data, bytes):      return data.decode('ascii')
    if isinstance(data, (str, int)): return str(data)
    if isinstance(data, dict):       return dict(map(convert, data.items()))
    if isinstance(data, tuple):      return tuple(map(convert, data))
    if isinstance(data, list):       return list(map(convert, data))
    if isinstance(data, set):        return set(map(convert, data))
    return data