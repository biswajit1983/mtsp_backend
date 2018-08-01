# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from functools import update_wrapper
from django.shortcuts import render
import gsm_utility.models as um
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils.decorators import classonlymethod
from django.views.decorators.http import require_GET, require_POST
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.apps import apps
from django.views import View
from django.db import DataError, IntegrityError
from django.forms.models import model_to_dict
import pdb
import json
import simplejson
from decimal import Decimal
from json import loads
from django.core import serializers
import re
from gsm_utility.utils import pluck, omit, set_response_header, EmailSendingUtil
from django.db import connection
from django.http import HttpResponse, HttpResponseBadRequest



class GSMView(View):
    @classonlymethod
    def as_view(cls, *initargs, **initkwargs):
        # pdb.set_trace()
        """
        Main entry point for a request-response process.
        """
        for key in initargs:
            if key in cls.http_method_names:
                raise TypeError("You tried to pass in the %s method name as a "
                                "keyword argument to %s(). Don't do that."
                                % (key, cls.__name__))
            if not hasattr(cls, key):
                raise TypeError("%s() received an invalid keyword %r. as_view "
                                "only accepts arguments that are already "
                                "attributes of the class." % (cls.__name__, key))

        def view(request, *args, **kwargs):
            self = cls(**initkwargs)
            # temp = initargs
            if hasattr(self, 'get') and not hasattr(self, 'head'):
                self.head = self.get
            self.request = request
            self.args = initargs
            self.kwargs = initkwargs
            # return self.dispatch(request, *args, **kwargs)
            return self.dispatch(request, *args, **kwargs)
        view.cls = cls
        view.initkwargs = initkwargs
        view.initargs = initargs

        # # take name and docstring from class
        update_wrapper(view, cls, updated=())
        #
        # # and possible attributes set by decorators
        # # like csrf_exempt from dispatch
        update_wrapper(view, cls.dispatch, assigned=())
        return view

    def dispatch(self, request, *args, **kwargs):
        # pdb.set_trace()
        # Try to dispatch to the right method; if a method doesn't exist,
        # defer to the error handler. Also defer to the error handler if the
        # request method isn't on the approved list.
        # print("highly %s"%(self.method_name))
        if hasattr(self,"method_name") and hasattr(self,self.method_name):
            if request.method.lower() in ['options']:
               handler = getattr(self, request.method.lower(), self.http_method_not_allowed)
            else:
               handler = getattr(self, self.method_name, self.http_method_not_allowed)
        elif hasattr(self,request.method.lower()):
            handler = getattr(self, request.method.lower(), self.http_method_not_allowed)
        else:
           handler = self.http_method_not_allowed
        return handler(request, *args, **kwargs)

    @method_decorator(set_response_header)
    def options(self,request,response,badResponse,*args,**kwarsg):
        """
        Handles responding to requests for the OPTIONS HTTP verb.
        """
        # response = http.HttpResponse()
        response['Allow'] = ', '.join(self._allowed_methods())
        response['Content-Length'] = '0'
        return response
