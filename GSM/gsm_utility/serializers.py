from gsm_utility.models import *
from rest_framework import routers, serializers, viewsets
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser


class GSMUsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = GSMUsers
        exclude = ('password','created_at','updated_at',)

class SessionTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = SessionToken
        exclude = ('salt','created_at','updated_at',)

class VerificationTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerificationToken
        exclude = ('salt','created_at','updated_at',)

class PasswordTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordToken
        exclude = ('salt','created_at','updated_at',)

class FeedbackSeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordToken
        exclude = ('created_at','updated_at',)
