# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.core.validators import RegexValidator, MaxValueValidator, MinValueValidator
from django.db.models.signals import pre_save
from django.dispatch import receiver
from pytz import timezone
from .utils import ChoiceEnum, get_MD5_encryption
from Crypto.Hash import MD5
import pdb

# Create your models here.

class Experience(ChoiceEnum):
    a = "0 years"
    b = "1 years"
    c = "1-2 years"
    d = "2-5 years"
    e = "5 years+"

class RiskAssets(ChoiceEnum):
    a = "$0 - $20,000"
    b = "$20,000 - $40,000"
    c = "$40,000 - $80,000"
    d = "$80,000 - $120,000"
    e = "$120,000+"

class GSMUsers(models.Model):
    id = models.AutoField(primary_key=True)
    # title = models.CharField(max_length=255,default="Mr.")
    first_name = models.CharField(max_length=255,blank=True)
    last_name = models.CharField(max_length=255,blank=True)
    password = models.CharField(max_length=255,blank=True)
    email = models.EmailField(max_length=255,default=None,unique=True)
    country = models.CharField(max_length=255,blank=True)
    house_number = models.CharField(max_length=10,blank=True)
    street = models.CharField(max_length=255,blank=True)
    city = models.CharField(max_length=255,blank=True)
    postcode = models.CharField(max_length=255,blank=True)
    number_validator = RegexValidator(r'(?:\+?\d{2})\d{10}',"enter a valid number like '+918888888888'")
    phone_number = models.CharField(max_length=15,default='+910000000000',validators=[number_validator],unique=False)
    verified = models.BooleanField(default=False)
    mail_sent = models.BooleanField(default=False)
    provider = models.CharField(max_length=255,blank=True)
    created_at = models.DateTimeField(auto_now_add=True,null=True)
    updated_at = models.DateTimeField(auto_now=True,null=True)
    tos_accepted = models.BooleanField(default=False)
    rd_accepted = models.BooleanField(default=False)
    deactivated_at = models.DateTimeField(null=True)    

    class Meta:
        managed = True
        db_table = 'gsm_user'

    def authenticate(self,pwd_to_check):
        #pdb.set_trace()
        if self.password:
            if self.password == get_MD5_encryption(pwd_to_check):
                return True
            else:
                return False
        else:
            return False


class Feedback(models.Model):
    id = models.AutoField(primary_key=True)
    gsm_user = models.ForeignKey('GSMUsers',on_delete=models.CASCADE)
    risk_assets = models.CharField(max_length=1,choices=RiskAssets.choices(),default='a')
    stock_trading_experience = models.CharField(max_length=1,choices=Experience.choices(),default='a')
    bond_trading_experience = models.CharField(max_length=1,choices=Experience.choices(),default='a')
    futures_trading_experience = models.CharField(max_length=1,choices=Experience.choices(),default='a')
    FX_trading_experience = models.CharField(max_length=1,choices=Experience.choices(),default='a')
    feedback = models.TextField(max_length=1000,blank=True,null=True)
    created_at = models.DateTimeField(auto_now_add=True,null=True)
    updated_at = models.DateTimeField(auto_now=True,null=True)

    class Meta:
        managed = True
        db_table = 'feedback'


class SessionToken(models.Model):
    id = models.AutoField(primary_key=True)
    salt = models.CharField(max_length=255,unique=True,null=False)
    session_token = models.CharField(max_length=255,unique=True,null=False)
    created_at = models.DateTimeField(auto_now_add=True,null=True)
    updated_at = models.DateTimeField(auto_now=True,null=True)
    valid_for  = models.IntegerField()#valid for 30minute converted into 30*60*1000ms
    gsm_user = models.ForeignKey(GSMUsers,on_delete=models.CASCADE)
    valid  = models.BooleanField(default=True)

    class Meta:
        managed = True
        unique_together = ('id','session_token')
        db_table = 'sessiontokens'


class VerificationToken(models.Model):
    id = models.AutoField(primary_key=True)
    salt = models.CharField(max_length=255,unique=True,null=False)
    verification_token = models.CharField(max_length=255,unique=True,null=False)
    created_at = models.DateTimeField(auto_now_add=True,null=True)
    updated_at = models.DateTimeField(auto_now=True,null=True)
    valid_for  = models.IntegerField()#valid for 30minute converted into 30*60*1000ms
    gsm_user = models.ForeignKey(GSMUsers,on_delete=models.CASCADE)
    valid  = models.BooleanField(default=True)

    class Meta:
        managed = True
        unique_together = ('id','verification_token')
        db_table = 'verificationtokens'

class PasswordToken(models.Model):
    id = models.AutoField(primary_key=True)
    salt = models.CharField(max_length=255,unique=True,null=False)
    password_token = models.CharField(max_length=255,unique=True,null=False)
    created_at = models.DateTimeField(auto_now_add=True,null=True)
    updated_at = models.DateTimeField(auto_now=True,null=True)
    valid_for  = models.IntegerField()#valid for 30minute converted into 30*60*1000ms
    gsm_user = models.ForeignKey(GSMUsers,on_delete=models.CASCADE)
    valid  = models.BooleanField(default=True)
    mail_sent = models.BooleanField(default=False)

    class Meta:
        managed = True
        unique_together = ('id','password_token')
        db_table = 'passwordtokens'

class TwitterOauthToken(models.Model):
    id = models.AutoField(primary_key=True)
    oauth_token = models.CharField(max_length=255,unique=True,null=False)
    oauth_token_secret = models.CharField(max_length=255,unique=True,null=False)
    created_at = models.DateTimeField(auto_now_add=True,null=True)
    updated_at = models.DateTimeField(auto_now=True,null=True)

    class Meta:
        managed = True
        unique_together = ('id','oauth_token')
        db_table = 'twitteroauthtokens'

class linkedinOauthState(models.Model):
    id = models.AutoField(primary_key=True)
    state = models.CharField(max_length=255,unique=True,null=False)
    created_at = models.DateTimeField(auto_now_add=True,null=True)
    updated_at = models.DateTimeField(auto_now=True,null=True)

    class Meta:
        managed = True
        unique_together = ('id','state')
        db_table = 'linkedinoauthstate'

class AtrData(models.Model):
    id = models.AutoField(primary_key=True)
    csiSym = models.CharField(max_length=4, null=False)
    date = models.IntegerField()
    open = models.DecimalField(decimal_places=4, max_digits=10)
    high = models.DecimalField(decimal_places=4, max_digits=10)
    low = models.DecimalField(decimal_places=4, max_digits=10)
    close = models.DecimalField(decimal_places=4, max_digits=10)
    volume = models.IntegerField()
    openInterest = models.IntegerField()
    contract = models.DecimalField(decimal_places=4, max_digits=10)
    seasonality = models.DecimalField(decimal_places=4, max_digits=10)
    atr20 = models.DecimalField(decimal_places=4, max_digits=10, null=True, blank=True)
    multiplier = models.IntegerField()
    usdAtr = models.DecimalField(decimal_places=4, max_digits=10, null=True, blank=True)
    changePercent = models.DecimalField(decimal_places=4, max_digits=10, null=True, blank=True)

class SignalsData(models.Model):
    id = models.AutoField(primary_key=True)
    csiSym = models.CharField(max_length=4, null=False)
    date = models.IntegerField()
    riskOn = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    riskOff = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    prev5 = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    prev10 = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    antiZz120 = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    zz30 = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    antiMlScalpAll = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    antiMlLastWorstFw = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    mlScalpBigFb = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    mlSwingBigFb = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    mlLastBestFb = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])
    antiSea = models.IntegerField(default=0, validators=[MaxValueValidator(1), MinValueValidator(-1)])

@receiver(pre_save,sender=GSMUsers)
def pre_save_password_encryption(sender, instance, raw, using, *args, **kwargs):
    if kwargs['update_fields'] and 'password' in kwargs['update_fields']:
        instance.password = get_MD5_encryption(instance.password)
    elif instance.password and not kwargs['update_fields']:
        instance.password = get_MD5_encryption(instance.password)
    else:
        pass
