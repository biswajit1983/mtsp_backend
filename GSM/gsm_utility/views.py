# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from functools import update_wrapper
from django.shortcuts import render
import gsm_utility.models as um
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils.decorators import classonlymethod
from django.views.decorators.http import require_GET, require_POST
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.apps import apps
from django.views import View
from django.template import Context, loader
from GSM.views import GSMView
from django.db import DataError, IntegrityError
from django.forms.models import model_to_dict
import pdb
import json
import simplejson
from decimal import Decimal
from json import loads
from django.core import serializers as django_serializers
import re
from .utils import *
from django.db import connection
from django.http import HttpResponse, HttpResponseBadRequest
from .serializers import *
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
from apiclient import discovery
import httplib2
import urllib
from oauth2client import client as google_client
import os
from django.conf import settings
import tweepy
import urllib.parse
import oauth2 as oauth
import pytz
from datetime import datetime, timedelta
from decimal import *

FACEBOOK_APP_ID = settings.API_KEYS['facebook']['app_id']
FACEBOOK_SECRET = settings.API_KEYS['facebook']['secret']
TWITTER_KEY = settings.API_KEYS['twitter']['key']
TWITTER_SECRET = settings.API_KEYS['twitter']['secret']
LINKEDIN_APP_ID = settings.API_KEYS['linkedin']['app_id']
LINKEDIN_SECRET = settings.API_KEYS['linkedin']['secret']
request_token_url='https://api.twitter.com/oauth/request_token'
access_token_url='https://api.twitter.com/oauth/access_token'
authorize_url='https://api.twitter.com/oauth/authorize'
credential_url='https://api.twitter.com/1.1/account/verify_credentials.json'
authorization_url_linkedin = "https://www.linkedin.com/oauth/v2/authorization"
redirect_uri_linkedin = settings.API_KEYS['linkedin']['redirect_uri']
access_token_url_linkedin = "https://www.linkedin.com/oauth/v2/accessToken"
data_url_linkedin = "https://api.linkedin.com/v1/people/~"

consumer = oauth.Consumer(TWITTER_KEY,TWITTER_SECRET)
# client = oauth.Client(consumer)
# oauth_token = None
# oauth_token_secret = None

# @csrf_exempt
# @set_response_header
# def email_sender_api(request,response,badResponse):
#     # #pdb.set_trace()
#     feedback_params = json.loads(request.body.decode('utf-8'))
#     email_keys = ['first_name','email']
#     gsm_users_keys = ['first_name','last_name','country','email']
#     email_params = pluck(feedback_params,email_keys)
#     gsm_users_params = pluck(feedback_params,gsm_users_keys)
#     feedback_params = omit(feedback_params,gsm_users_keys)
#     # gsm_users_params.update({'user'})
#     try:
#         gsm_usr_obj = um.GSMUsers.objects.get(email=gsm_users_params['email'])
#     except Exception:
#         try:
#             gsm_usr_obj = um.GSMUsers(**gsm_users_params)
#             gsm_usr_obj.save()
#         except Exception as e:
#             print(e)
#             message = str(e)
#             return badResponse.write("%s"%json.dumps({'Message':message}))
#     feedback_params.update({'gsm_user':gsm_usr_obj})
#     try:
#         feedback_obj = um.Feedback(**feedback_params)
#         feedback_obj.save()
#     except Exception as e:
#         print(e)
#         message = str(e)
#         return badResponse.write("%s"%json.dumps({'Message':message}))
#     try:
#         status,res = email_sender(email_params)
#         response_sendgrid = {}
#         response_sendgrid['status']=status
#         response_sendgrid['response']=res
#         response_sendgrid['success']=True
#         # response_sendgrid['status']=200
#         response.write("%s"%(json.dumps(response_sendgrid)))
#         return response
#         # return HttpResponse(json.dumps(response_sendgrid),content_type="application/json")
#     except Exception as e:
#         print(e)
#         message = str(e)
#         return badResponse.write("%s"%json.dumps({'Message':message}))

decorators = [csrf_exempt, set_response_header]
decorators_extended = [csrf_exempt, set_response_header,session_token_required]
class FeedbackView(GSMView):

    @method_decorator(decorators)
    def get(self,request,response,badResponse,*args,**kwargs):
        #pdb.set_trace()
        '''hasattr(request.GET,'id')'''
        if 'id' in request.GET.keys():
            feedback_id = request.GET.get('id','')
            try:
                f_obj = model_to_dict(um.Feedback.objects.get(pk=feedback_id))
            except Exception as e:
                print(e)
                message = str(e)
                badResponse.write("%s"%(json.dumps({'Message':message})))
                return badResponse
            response.write("%s"%(json.dumps({'feedback':f_obj})))
            return response
        else:
            f_objs = dict(map(lambda x: (x.get('pk'),x.get('fields')),json.loads(django_serializers.serialize('json',um.Feedback.objects.all()))))
            response.write("%s"%(json.dumps({'feedbacks':f_objs})))
            return response

    @method_decorator(decorators)
    def post(self,request,response,badResponse,*args,**kwarsg):
        feedback_params = json.loads(request.body.decode('utf-8'))
        email_keys = ['first_name','email']
        gsm_users_keys = ['first_name','last_name','country','email']
        email_params = pluck(feedback_params,email_keys)
        gsm_users_params = pluck(feedback_params,gsm_users_keys)
        feedback_params = omit(feedback_params,gsm_users_keys)
        risk_assets = um.RiskAssets.reverse_dict()[feedback_params['risk_assets']]
        exp_params_list = ['stock_trading_experience','bond_trading_experience','futures_trading_experience','FX_trading_experience']
        expand_feedback_params = feedback_params.copy()
        map(lambda i:expand_feedback_params.update({i:um.Experience.reverse_dict()[expand_feedback_params[i]]}),exp_params_list)
        email_sender = EmailSendingUtil(email_context={'feedback': expand_feedback_params, 'user': gsm_users_params, 'risk_assets': risk_assets}, to=["hidemi@globalsystemsmanagement.net"], cc=["dream@cloudsmiths.io", "biswajit1983@gmail.com", "shubhammshr621@gmail.com"], subject="You got a new message from " + email_params['first_name'],
                                        from_email=email_params['email'],template_path="utility/welcome.html")
        gsm_user_util = GSMUsersUtils(params=gsm_users_params)
        try:
            gsm_usr_obj = gsm_user_util.findOrCreate()
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse
        feedback_params.update({'gsm_user':gsm_usr_obj})
        try:
            feedback_obj = um.Feedback(**feedback_params)
            feedback_obj.save()
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse
        try:
            # status,res = email_sender(email_params)
            res = email_sender.send()
            # response_sendgrid = {}
            # response_sendgrid['status']=status
            # response_sendgrid['response']=res
            # response_sendgrid['success']=True
            # response_sendgrid['status']=200
            response.write("%s"%(json.dumps(res)))
            return response
            # return HttpResponse(json.dumps(response_sendgrid),content_type="application/json")
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse

    @method_decorator(decorators)
    def delete(self,request,response,badResponse,*args,**kwargs):
        # #pdb.set_trace()
        # print("I'm delete")
        '''hasattr(request.GET,'id')'''
        feedback_id = json.loads(request.body.decode('utf-8'))['id']
        try:
            um.Feedback.objects.filter(pk=feedback_id).delete()
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse
        # response.write("%s"%(json.dumps({'feedback':f_obj})))
        return response

    @method_decorator(decorators)
    def patch(self,request,response,badResponse,*args,**kwargs):
        # #pdb.set_trace()
        feedback_params = json.loads(request.body.decode('utf-8'))
        # feedback_id = json.loads(request.body.decode('utf-8'))['id']
        try:
            um.Feedback.objects.filter(pk=feedback_params['id']).update(**omit(feedback_params,['id']))
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse
        # response.write("%s"%(json.dumps({'feedback':f_obj})))
        return response

    @method_decorator(decorators)
    def test(self,request,response,badResponse,*args,**kwargs):
        print("Test successful")
        return response

class AllChoiceView(View):
    @method_decorator(decorators)
    def get(self,request,response,badResponse,*args,**kwargs):
        choices = {}
        choices['experience'] = um.Experience.reverse_dict()
        choices['risk_assets'] = um.RiskAssets.reverse_dict()
        response.write("%s"%(json.dumps(choices)))
        return response

class AuthenticationView(GSMView):
    @method_decorator(decorators)
    def signup(self,request,response,badResponse,*args,**kwargs):
        gsm_users_params = json.loads(request.body.decode('utf-8'))
        gsm_user_util = GSMUsersUtils(params=gsm_users_params)
        try:
            gsm_usr_obj = gsm_user_util.findOrCreate()
            if gsm_usr_obj.verified:
                res = {"Message":"Account is already verified..Try your login credential to login!!!"}
            else:
                vtoken = VerificationTokenUtils(gsm_user=gsm_usr_obj.id)
                res = vtoken.send_mail(gsm_usr_obj)
            response.write("%s"%(json.dumps(convert(res))))
            return response
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse

        # if not hasattr(gsm_usr_obj,'password')
    @method_decorator(decorators)
    def login(self,request,response,badResponse,*args,**kwargs):
        # ##pdb.set_trace()
        login_params = json.loads(request.body.decode('utf-8'))
        gsm_user_util = GSMUsersUtils(params={'email':login_params['email']})
        try:
            gsm_usr_obj = gsm_user_util.findOrCreate()
            stoken = SessionTokenUtils(gsm_user=gsm_usr_obj.id)
            # res = vtoken.send_mail()
            res = {}
            if gsm_usr_obj.verified and gsm_usr_obj.authenticate(login_params['password']):
            # if gsm_usr_obj.authenticate(login_params['password']):
                res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
                res['user'] = GSMUsersSerializer(gsm_usr_obj).data
                # res['user'] = JSONRenderer().render(GSMUsersSerializer(gsm_usr_obj).data)
                response.write("%s"%(json.dumps(res)))
                return response
            else:
                raise ValidationError("login not successful!!!")
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse

    @method_decorator(decorators_extended)
    def logout(self,request,response,badResponse,*args,**kwargs):
        #pdb.set_trace()
        stoken = request.META['HTTP_SESSIONTOKEN']
        try:
            stoken.expireToken()
            res = {"Message":"Log out successful!!"}
            response.write("%s"%(json.dumps(res)))
            return response
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse

    @method_decorator(decorators)
    def verification(self,request,response,badResponse,*args,**kwargs):
        #pdb.set_trace()
        # stoken = request.META['HTTP_SESSIONTOKEN']
        # user_obj = request.META['HTTP_AUTHENTICATED_USER']
        verification_params = json.loads(request.body.decode('utf-8'))
        res = {}
        # gsm_user_util = GSMUsersUtils(params=user)
        try:
            # stoken.expireToken()
            vtoken = VerificationTokenUtils(verification_token=verification_params['token'])
            usr_obj = vtoken.token.gsm_user if isinstance(vtoken.token.gsm_user,GSMUsers) else um.GSMUsers.objects.get(pk=verification_params['id'])
            if vtoken.isValid() and vtoken.token.gsm_user.id == verification_params['id']:
                usr_obj.verified = True
                usr_obj.save(update_fields=['verified'])
                vtoken.expireToken()
                stoken = SessionTokenUtils(gsm_user=usr_obj.id)
                res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
                res['user'] = GSMUsersSerializer(usr_obj).data
                res["Message"] = "verified successfully!!!"
                response.write("%s"%(json.dumps(res)))
                return response
            else:
                vtoken.expireToken()
                raise ValidationError("verification token not matched properly with our criteria")
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse

    @method_decorator(decorators)
    def forgot_password(self,request,response,badResponse,*args,**kwargs):
        forgot_password_params = json.loads(request.body.decode('utf-8'))
        gsm_user_util = GSMUsersUtils(params={'email':forgot_password_params['email']})
        try:
            gsm_usr_obj = gsm_user_util.findOrCreate()
            # stoken = SessionTokenUtils(gsm_user=gsm_usr_obj.id,flag='skipNew')
            # if not stoken.token is None and stoken.isValid():
            #     stoken.expireToken()
            ptoken = PasswordTokenUtils(gsm_user=gsm_usr_obj.id)
            res = ptoken.send_mail(gsm_usr_obj)
            response.write("%s"%(json.dumps(convert(res))))
            return response
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse

    @method_decorator(decorators)
    def change_password(self,request,response,badResponse,*args,**kwargs):
        change_password_params = json.loads(request.body.decode('utf-8'))
        res = {}
        try:
            ptoken = PasswordTokenUtils(password_token=change_password_params['token'])
            usr_obj = ptoken.token.gsm_user if isinstance(ptoken.token.gsm_user,GSMUsers) else um.GSMUsers.objects.get(pk=change_password_params['id'])
            if ptoken.isValid() and ptoken.token.gsm_user.id == change_password_params['id']:
                ptoken.expireToken()
                # gsm_usr_obj = GSMUsersUtils(params={'email':change_password_params['email']})
                usr_obj.password = change_password_params['password']
                if not usr_obj.verified:
                    usr_obj.verified = True
                    usr_obj.save(update_fields=['password','verified'])
                else:
                    usr_obj.save(update_fields=['password'])
                stoken = SessionTokenUtils(gsm_user=usr_obj.id)
                res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
                res['user'] = GSMUsersSerializer(usr_obj).data
                res["Message"] = "Password Changed successfully!!!"
                response.write("%s"%(json.dumps(res)))
                return response
            else:
                raise ValidationError("password token not matched properly with our criteria")
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse


    @method_decorator(decorators)
    def google_auth(self,request,response,badResponse,*args,**kwargs):
        # pdb.set_trace()
        auth_code = json.loads(request.body.decode('utf-8'))['auth_code']
        # try:
        credentials = google_client.credentials_from_clientsecrets_and_code(
            settings.CLIENT_SECRET_FILE,
            # ['https://www.googleapis.com/plus/v1/people/me'],
            ["https://www.googleapis.com/auth/plus.me","https://www.googleapis.com/auth/userinfo.profile"], #Important: Use different scopes to use different google apis
            auth_code)
        http_auth = credentials.authorize(httplib2.Http())
        user_service = discovery.build('oauth2', 'v1', http=http_auth)
        userinfo = user_service.userinfo().get().execute()
        gsm_user_util = GSMUsersUtils(params={'email':userinfo['email'],'first_name':userinfo['given_name'],'last_name':userinfo['family_name']})
        gsm_usr_obj = gsm_user_util.findOrCreate()
        if not gsm_usr_obj.verified:
            gsm_usr_obj.verified = True
            gsm_usr_obj.save(update_fields=['verified'])
        stoken = SessionTokenUtils(gsm_user=gsm_usr_obj.id)
        vtoken = VerificationTokenUtils(gsm_user=gsm_usr_obj.id)
        vtoken.expireToken()
        res = {}
        res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
        # res['user'] = JSONRenderer().render(GSMUsersSerializer(gsm_usr_obj).data)
        res['user'] = GSMUsersSerializer(gsm_usr_obj).data
        response.write("%s"%(json.dumps(res)))
        return response
        # except Exception as e:
        #     print(e)
        #     message = str(e)
        #     badResponse.write("%s"%(json.dumps({'Message':message})))
        #     return badResponse

    @method_decorator(decorators)
    def fb_auth(self,request,response,badResponse,*args,**kwargs):
        fb_auth_params = json.loads(request.body.decode('utf-8'))
        try:
            INPUT_TOKEN = fb_auth_params['input_token']
            gsm_users_params = omit(fb_auth_params['user_details'],['id'])
            gsm_user_util = GSMUsersUtils(params=gsm_users_params)
            data={'client_id':FACEBOOK_APP_ID,'client_secret':FACEBOOK_SECRET,'grant_type':'client_credentials'}
            body = urllib.parse.urlencode(data)
            h = httplib2.Http()
            resp, content = h.request("https://graph.facebook.com/oauth/access_token?", method="POST", body=body)
            if resp.status == 200:
                # ACCESS_TOKEN = re.split('=',content)[1]
                ACCESS_TOKEN = json.loads(content.decode('utf-8'))['access_token']
                resp, content = h.request("https://graph.facebook.com/debug_token?input_token=%s&access_token=%s"%(INPUT_TOKEN,ACCESS_TOKEN), method="GET")
                validation_params={}
                validation_params=(json.loads(content.decode('utf-8')))['data']
                if resp.status == 200 and validation_params['app_id']==FACEBOOK_APP_ID and validation_params['user_id']==fb_auth_params['user_details']['id'] and validation_params['is_valid']:
                    gsm_usr_obj = gsm_user_util.findOrCreate()
                    if not gsm_usr_obj.verified:
                        gsm_usr_obj.verified = True
                        gsm_usr_obj.save(update_fields=['verified'])
                    stoken = SessionTokenUtils(gsm_user=gsm_usr_obj.id)
                    vtoken = VerificationTokenUtils(gsm_user=gsm_usr_obj.id,flag='skipNew')
                    if not vtoken.token is None and vtoken.isValid():
                        vtoken.expireToken()
                    res = {}
                    res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
                    res['user'] = GSMUsersSerializer(gsm_usr_obj).data
                    response.write("%s"%(json.dumps(res)))
                    return response
                else:
                    raise ValidationError("Facebook didn't recognize this attempt to login!!!")
            else:
                raise ValidationError("Facebook didn't recognize this attempt to login!!!")
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse


    @method_decorator(decorators)
    def twitter_auth(self,request,response,badResponse,*args,**kwargs):
        # pdb.set_trace()
        # fb_auth_params = json.loads(request.body.decode('utf-8'))
        global consumer
        try:
            # consumer=oauth.Consumer(TWITTER_KEY,TWITTER_SECRET)
            client=oauth.Client(consumer)
            resp, content = client.request(request_token_url, "GET")

            if resp['status'] != '200':
                raise Exception("Invalid response %s...%s"%(resp['status'],content))

            request_token = dict(urllib.parse.parse_qsl(content.decode('utf-8')))
            # global oauth_token,oauth_token_secret
            oauth_token = request_token['oauth_token']
            oauth_token_secret = request_token['oauth_token_secret']
            ttoken_params = {'oauth_token':oauth_token,'oauth_token_secret':oauth_token_secret}

            ttoken = um.TwitterOauthToken(**ttoken_params)
            ttoken.save()
            # res = {"Message":"Hello users[%s]!!!"%(request.GET.get('id'))}
            res = {"authorize_url":"%s?oauth_token=%s"%(authorize_url,oauth_token)}
            response.write("%s"%(json.dumps(res)))
            return response
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse

    @method_decorator(decorators)
    def twitter_auth_callback(self,request,response,badResponse,*args,**kwargs):
        # pdb.set_trace()
        global consumer
        # fb_auth_params = json.loads(request.body.decode('utf-8'))
        try:
            oauth_verifier = request.GET.get('oauth_verifier')
            oauth_token = request.GET.get('oauth_token')
            oauth_token_secret = model_to_dict(um.TwitterOauthToken.objects.get(oauth_token=oauth_token))['oauth_token_secret']
            token = oauth.Token(oauth_token,oauth_token_secret)
            token.set_verifier(oauth_verifier)
            client = oauth.Client(consumer, token)
            resp, content = client.request(access_token_url, "POST")
            if resp['status'] != '200':
                raise Exception("Invalid response %s...%s"%(resp['status'],content))
            access_token = dict(urllib.parse.parse_qsl(content))

            oauth_token_new = access_token['oauth_token']
            oauth_token_secret_new = access_token['oauth_token_secret']
            token_new = oauth.Token(oauth_token_new,oauth_token_secret_new)
            # token.set_verifier(oauth_verifier)
            client_new = oauth.Client(consumer, token_new)
            params = urllib.parse.urlencode({"include_email":'true','skip_status':'true','include_entities':'false'})
            final_url = (credential_url+"?%s"%(params))
            resp, content = client_new.request(final_url, "GET")
            if resp['status'] != '200':
                raise Exception("Invalid response %s...%s"%(resp['status'],content))
            user_data = json.loads(content.decode('utf-8'))
            user_params = {'first_name':user_data['name'].split(' ')[0],'last_name':user_data['name'].split(' ')[1],'email':user_data['email']}
            gsm_user_util = GSMUsersUtils(params=user_params)
            gsm_usr_obj = gsm_user_util.findOrCreate()
            if not gsm_usr_obj.verified:
                gsm_usr_obj.verified = True
                gsm_usr_obj.save(update_fields=['verified'])
            stoken = SessionTokenUtils(gsm_user=gsm_usr_obj.id)
            vtoken = VerificationTokenUtils(gsm_user=gsm_usr_obj.id,flag='skipNew')
            if not vtoken.token is None and vtoken.isValid():
                vtoken.expireToken()
            res = {}
            res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
            res['user'] = GSMUsersSerializer(gsm_usr_obj).data
            res['Message'] = "TWITTER_AUTH_SUCCESS"
            response['content-type'] = 'text/html'
            template = loader.get_template("utility/twitter_auth_response.html")
            response.write(template.render(context={'response': json.dumps(res)}))
            return response
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse

    @method_decorator(decorators)
    def linkedin_auth(self,request,response,badResponse,*args,**kwargs):
        # pdb.set_trace()
        # fb_auth_params = json.loads(request.body.decode('utf-8'))
        # global consumer,client
        try:
            lstate_params = {'state':random_string(16)}
            lstate_obj = um.linkedinOauthState(**lstate_params)
            lstate_obj.save()
            params = urllib.parse.urlencode({'response_type':'code','client_id':LINKEDIN_APP_ID,'redirect_uri':redirect_uri_linkedin,'state':lstate_obj.state,'scope':'r_basicprofile r_emailaddress'})
            res = {"authorize_url":"%s?%s"%(authorization_url_linkedin,params)}
            response.write("%s"%(json.dumps(res)))
            return response
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse

    @method_decorator(decorators)
    def linkedin_auth_callback(self,request,response,badResponse,*args,**kwargs):
        # pdb.set_trace()
        try:
            state = request.GET.get('state')
            code = request.GET.get('code')
            try:
                lstate_obj = um.linkedinOauthState.objects.get(state=state)
            except Exception as e:
                if e.__class__.__name__ == "DoesNotExist":
                    raise Exception("Unauthorized attempt to login with linkedin")
                else:
                    raise
            h = httplib2.Http()
            params = urllib.parse.urlencode({'grant_type':'authorization_code','code':code,'redirect_uri':redirect_uri_linkedin,'client_id':LINKEDIN_APP_ID,'client_secret':LINKEDIN_SECRET})
            headers = {"Content-Type":"application/x-www-form-urlencoded"}
            resp, content = h.request(access_token_url_linkedin,method='POST',body=params,headers=headers)
            access_token = json.loads(content.decode('utf-8'))
            if resp['status'] != '200':
                raise Exception("Invalid response %s...%s"%(resp['status'],content))

            headers = {"Host":"api.linkedin.com","Connection":"Keep-Alive","Authorization":"Bearer %s"%(access_token['access_token'])}
            resp, content = h.request(data_url_linkedin+":(first_name,last_name,email-address)?format=json",method='GET',headers=headers)
            if resp['status'] != '200':
                raise Exception("Invalid response %s...%s"%(resp['status'],content))
            user_data = json.loads(content.decode('utf-8'))
            user_params = {'first_name':user_data['firstName'],'last_name':user_data['lastName'],'email':user_data['emailAddress']}
            gsm_user_util = GSMUsersUtils(params=user_params)
            gsm_usr_obj = gsm_user_util.findOrCreate()
            if not gsm_usr_obj.verified:
                gsm_usr_obj.verified = True
                gsm_usr_obj.save(update_fields=['verified'])
            stoken = SessionTokenUtils(gsm_user=gsm_usr_obj.id)
            vtoken = VerificationTokenUtils(gsm_user=gsm_usr_obj.id,flag='skipNew')
            if not vtoken.token is None and vtoken.isValid():
                vtoken.expireToken()
            res = {}
            res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
            res['user'] = GSMUsersSerializer(gsm_usr_obj).data
            res['Message'] = "LINKEDIN_AUTH_SUCCESS"
            response['content-type'] = 'text/html'
            template = loader.get_template("utility/linkedin_auth_response.html")
            response.write(template.render(context={'linkedin_response': json.dumps(res)}))
            return response
        except Exception as e:
            print(e)
            message = str(e)
            badResponse.write("%s"%(json.dumps({'Message':message})))
            return badResponse


    @method_decorator(decorators_extended)
    def tos_update(self, request, response, badResponse, *args, **kwargs):
        stoken = request.META['HTTP_SESSIONTOKEN']
        res = {}
        try:
            if request.method == 'POST':
                user = stoken.token.gsm_user
                user.tos_accepted = True
                user.save(update_fields=['tos_accepted'])
                res['user'] = GSMUsersSerializer(user).data
                res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
                response.write("%s"%(json.dumps(res)))
                return response
            else:
                raise ValidationError("INVALID_REQUEST")
        except Exception as e:
            print(e)
            badResponse.write("%s"%(json.dumps({'Message':str(e)})))
            return badResponse


    @method_decorator(decorators_extended)
    def rd_update(self, request, response, badResponse, *args, **kwargs):
        try:
            params = json.loads(request.body.decode('utf-8'))
            stoken = request.META['HTTP_SESSIONTOKEN']
            res = {}
            if request.method == 'POST':
                user = stoken.token.gsm_user
                user.rd_accepted = True
                user.save(update_fields=['rd_accepted'])
                res['user'] = GSMUsersSerializer(user).data
                res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
                response.write("%s"%(json.dumps(res)))
                return response
            else:
                raise ValidationError("INVALID_REQUEST")
        except Exception as e:
            print(e)
            badResponse.write("%s"%(json.dumps({'Message': str(e)})))
            return badResponse

    @method_decorator(decorators_extended)
    def update(self, request, response, badResponse, *args, **kwargs):
        try:
            res={}
            params = json.loads(request.body.decode('utf-8'))
            stoken = request.META['HTTP_SESSIONTOKEN']
            user = stoken.token.gsm_user
            allowed_params = ['first_name', 'last_name', 'city', 'country', 'password', 'house_number', 'street', 'postcode', 'phone_number']
            update_array = []
            for key in params:
                if hasattr(user, key) and key in allowed_params:
                    setattr(user, key, params[key])
                    update_array.append(key)
                else:
                    raise ValidationError("INVALID_PARAMS")
            user.save(update_fields=update_array)
            res['user'] = GSMUsersSerializer(user).data
            res['sessiontoken'] = stoken.token.__dict__[stoken.token_name]
            response.write("%s"%(json.dumps(res)))
            return response
        except Exception as e:
            print(e)
            badResponse.write("%s"%(json.dumps({'Message': str(e)})))
            return badResponse

    @method_decorator(decorators_extended)
    def deactivate(self, request, response, badResponse, *args, **kwargs):
        try:
            res={}
            params = json.loads(request.body.decode('utf-8'))
            stoken = request.META['HTTP_SESSIONTOKEN']
            user = stoken.token.gsm_user
            user.deactivated_at = datetime.now().replace(tzinfo=pytz.utc)
            user.save(update_fields=['deactivated_at'])
            res['Message'] = 'DEACTIVATE_SUCCESS'
            response.write("%s"%(json.dumps(res)))
            return response
        except Exception as e:
            print(e)
            badResponse.write("%s"%(json.dumps({'Message': str(e)})))
            return badResponse
    
    @method_decorator(decorators_extended)
    def reactivate(self, request, response, badResponse, *args, **kwargs):
        try:
            res={}
            params = json.loads(request.body.decode('utf-8'))
            stoken = request.META['HTTP_SESSIONTOKEN']
            user = stoken.token.gsm_user
            user.deactivated_at = None
            user.save(update_fields=['deactivated_at'])
            res['Message'] = 'REACTIVATE_SUCCESS'
            response.write("%s"%(json.dumps(res)))
            return response
        except Exception as e:
            print(e)
            badResponse.write("%s"%(json.dumps({'Message': str(e)})))
            return badResponse

    @method_decorator(decorators)
    def test_method(self,request,response,badResponse,*args,**kwargs):
        res = {"Message":"Hello users[%s]!!!"%(request.GET.get('id'))}
        response.write("%s"%(json.dumps(res)))
        return response


class ATRChartView(GSMView):
    @method_decorator(decorators)
    def post(self, request, response, badResponse, *args, **kwargs):
        # example request.body
        # {"portfolio": ["TU", "BO"], "systems": ["prev1", "prev5"], "target": 500, "account": 5000}
        # um.AtrData.objects
        # endDate = int(datetime.now().strftime("%Y%m%d"))
        lookback = 24
        referenceDate = datetime(2018, 2, 10)
        endDate = int(referenceDate.strftime("%Y%m%d"))
        params = json.loads(request.body.decode("utf_8"))
        if all(key in params for key in ['portfolio', 'systems', 'target', 'account']):
            dates = list(map(lambda x: x.date, AtrData.objects.filter(date__lte=endDate, csiSym="ES").order_by('-date')[:24]))
            dates = list(reversed(dates))
            # pdb.set_trace()
            startDate = dates[0]
            target = Decimal(params['target'])
            account = params["account"]
            
            atrData = [i for i in um.AtrData.objects.filter(csiSym__in=(params['portfolio'] + ['ES']), date__in=dates).values()]            
            signalsData = [i for i in um.SignalsData.objects.filter(csiSym__in=params['portfolio'] + ["ES"], date__in=dates).values()]
            
            pnlData = [{'date': startDate, "pnl": account, "changePercent": 0, "cumulative": 0}]
            benchmarkData = [{'date': startDate, "pnl": account, "changePercent": 0, "cumulative": 0}]
            antiPnlData = [{'date': startDate, "pnl": account, "changePercent": 0, "cumulative": 0}]
            antiBenchmarkData = [{'date': startDate, "pnl": account, "changePercent": 0, "cumulative": 0}]
            i = 1
            for date in dates[1:23]:
                prevAccountValue = pnlData[len(pnlData) - 1]["pnl"]
                antiPrevAccountValue = antiPnlData[len(antiPnlData) - 1]["pnl"]
                benchmarkPrevAccountValue = benchmarkData[len(benchmarkData) - 1]["pnl"]
                antiBenchmarkPrevAccountValue = antiBenchmarkData[len(antiBenchmarkData) - 1]["pnl"]
                pnl = Decimal(0)
                antiPnl = Decimal(0)
                benchmark = Decimal(0)
                antiBenchmark = Decimal(0)
                for contract in params['portfolio']:
                    try:
                        # yesterdayAtrObj = atrData.get(csiSym=contract, date=dates[i-1])
                        yesterdayAtrObj = [i for i in filter(lambda x : x['csiSym']==contract and x['date']==dates[i-1], atrData)][0]
                        # todayAtrObj = atrData.get(csiSym=contract, date=date)
                        todayAtrObj = [i for i in filter(lambda x : x['csiSym']==contract and x['date']==date, atrData)][0]
                    except AtrData.DoesNotExist:
                        print(str(date) + '---------------' + contract)
                        continue
                    qty = int(target/yesterdayAtrObj['usdAtr']) or 1
                    dailyPnl = qty*todayAtrObj['changePercent']*yesterdayAtrObj['contract']
                    resultSignal = 0
                    for system in params['systems']:
                        # signalsObj = signalsData.get(csiSym=contract, date=date)
                        signalsObj = [ i for i in filter(lambda x: x['csiSym'] == contract and x['date'] == date, signalsData)][0]
                        # resultSignal += getattr(signalsObj, system)
                        resultSignal += signalsObj[system]   
                    if len(params['systems']) % 2 == 0:
                        resultSignal = resultSignal or 1
                    if resultSignal < 0:
                        resultSignal = -1
                    elif resultSignal > 0:
                        resultSignal = 1
                    else:
                        resultSignal = 0
                    pnl += dailyPnl*resultSignal
                    antiPnl -= dailyPnl*resultSignal
                
                # Benchmark calculation
                # yesterdayAtrObj = atrData.get(csiSym="ES", date=dates[i-1])
                # todayAtrObj = atrData.get(csiSym="ES", date=date)
                yesterdayAtrObj = [i for i in filter(lambda x : x['csiSym']=="ES" and x['date']==dates[i-1], atrData)][0]
                todayAtrObj = [i for i in filter(lambda x : x['csiSym']=="ES" and x['date']==date, atrData)][0]

                qty = int(target/yesterdayAtrObj['usdAtr']) or 1
                dailyPnl = qty*todayAtrObj['changePercent']*yesterdayAtrObj['contract']
                resultSignal = 0
                for system in params['systems']:
                    # signalsObj = signalsData.get(csiSym="ES", date=date)
                    signalsObj = [ i for i in filter(lambda x: x['csiSym'] == contract and x['date'] == date, signalsData)][0]
                    # resultSignal += getattr(signalsObj, system)
                    resultSignal += signalsObj[system]
                    resultSignal += signalsObj[system]
                if len(params['systems']) % 2 == 0:
                    resultSignal = resultSignal or 1
                if resultSignal < 0:
                    resultSignal = -1
                elif resultSignal > 0:
                    resultSignal = 1
                else:
                    resultSignal = 0
                benchmark += dailyPnl*resultSignal
                antiBenchmark -= dailyPnl*resultSignal

                #append results
                # pdb.set_trace()
                pnlData.append({"date": date,
                    "pnl": prevAccountValue + pnl,
                    'changePercent': pnl/prevAccountValue,
                    "cumulative": (prevAccountValue + pnl - account)/account
                })
                antiPnlData.append({"date": date,
                    "pnl": antiPrevAccountValue + antiPnl,
                    'changePercent': antiPnl/antiPrevAccountValue,
                    "cumulative": (antiPrevAccountValue + antiPnl - account)/account
                })
                benchmarkData.append({"date": date,
                    "pnl": benchmarkPrevAccountValue + benchmark,
                    'changePercent': benchmark/benchmarkPrevAccountValue,
                    "cumulative": (benchmarkPrevAccountValue + benchmark - account)/account
                })
                antiBenchmarkData.append({"date": date,
                    "pnl": antiBenchmarkPrevAccountValue + antiBenchmark,
                    'changePercent': antiBenchmark/antiBenchmarkPrevAccountValue,
                    "cumulative": (antiBenchmarkPrevAccountValue + antiBenchmark - account)/account
                })
                i = i + 1

            # for i in range(0, len(pnlData) - 2):
            #     pnlData[i+1]["cumulative"] = pnlData[i]["cumulative"] + pnlData[i+1]["changePercent"]
            #     antiPnlData[i+1]["cumulative"] = antiPnlData[i]["cumulative"] + antiPnlData[i+1]["changePercent"]
            #     benchmarkData[i+1]["cumulative"] = benchmarkData[i]["cumulative"] + benchmarkData[i+1]["changePercent"]
            #     antiBenchmarkData[i+1]["cumulative"] = antiBenchmarkData[i]["cumulative"] + antiBenchmarkData[i+1]["changePercent"]
            
            response.write("%s"%(json.dumps({
                'pnlData': convert(pnlData),
                'antiPnlData': convert(antiPnlData),
                'benchmarkData': convert(benchmarkData),
                'antiBenchmarkData': convert(antiBenchmarkData)
            })))

            return response


class RankingChartView(GSMView):
    @method_decorator(decorators)
    def post(self, request, response, badResponse, *args, **kwargs):
        # example request.body
        # {"accounts": [
        #   {
        #       "portfolio": ["TU", "BO"],
        #       "target": "500",
        #       "accountValue": 5000
        #   }],
        # "slots": [
        #   {
        #        "position": 1,
        #        "systems": ["prev1", "prev5"]
        #   },
        #   {
        #        "position": 2,
        #        "systems": ["lowEq", "antiHighEq"]
        #   }],
        # "lookback": 23}
        params = json.loads(request.body.decode("utf_8"))
        accounts = params["accounts"]
        lookback = params['lookback']
        slots = params['slots']


        # looping through all the trading systems
        # Better would be to keep a global constant, for now I am just hardcoding
        for system in set([f.name for f in um.SignalsData._meta.get_fields()]) - set(['csiSym', 'id', 'date']):
            slots.append({
                "position": system,
                "systems": [system]
            })
        referenceDate = datetime(2018, 2, 10)
        endDate = int(referenceDate.strftime("%Y%m%d"))
        dates = list(map(lambda x: x.date, AtrData.objects.filter(date__lte=endDate, csiSym="ES").order_by('-date')[:lookback + 1]))
        dates = list(reversed(dates))
        startDate = dates[0]
        result = []
        # res['accounts'] = []
        for account in accounts:
            # pdb.set_trace()
            atrData = [i for i in um.AtrData.objects.filter(csiSym__in=account['portfolio'], date__in=dates).values()]
            signalsData = [i for i in um.SignalsData.objects.filter(csiSym__in=account['portfolio'], date__in=dates).values()]


            target = Decimal(account['target'])
            accountValue = account['accountValue']
            accountResult = []
            for slot in slots:
                slotResult = []
                cumulativeChangePercent = 0
                value = accountValue
                i = 1
                for date in dates[1:lookback+1]:
                    pnl = 0
                    for contract in account['portfolio']:
                        # pdb.set_trace()
                        # yesterdayAtrObj = atrData.get(csiSym=contract, date=dates[i-1])
                        yesterdayAtrObj = [i for i in filter(lambda x : x['csiSym']==contract and x['date']==dates[i-1],atrData)][0]
                        # todayAtrObj = atrData.get(csiSym=contract, date=date)
                        todayAtrObj = [i for i in filter(lambda x : x['csiSym']==contract and x['date']==date,atrData)][0]
                        qty = int(target/yesterdayAtrObj['usdAtr']) or 1
                        dailyPnl = qty*todayAtrObj['changePercent']*yesterdayAtrObj['contract']
                        resultSignal = 0
                        for system in slot["systems"]:
                            # signalsObj = signalsData.get(csiSym=contract, date=date)
                            signalsObj = [ i for i in filter(lambda x: x['csiSym'] == contract and x['date'] == date,signalsData)][0]
                            resultSignal += signalsObj[system]
                        if len(slot['systems']) % 2 == 0:
                            resultSignal = resultSignal or 1
                        if resultSignal < 0:
                            resultSignal = -1
                        elif resultSignal > 0:
                            resultSignal = 1
                        else:
                            resultSignal = 0
                        pnl += resultSignal*dailyPnl
                    value += pnl
                    cumulativeChangePercent = (value - accountValue)/accountValue
                    if(i in [1,5,20]):
                        slotResult.append({
                            "lookback": i,
                            "changePercent": cumulativeChangePercent
                        })
                    i = i + 1
                accountResult.append({
                    "position": slot["position"],
                    "result": slotResult
                })
            result.append({
                "accountResult": accountResult,
                "account": account
            })
        
        response.write("%s"%(json.dumps({
            "rankingData": convert(result)
        })))

        return response

        
