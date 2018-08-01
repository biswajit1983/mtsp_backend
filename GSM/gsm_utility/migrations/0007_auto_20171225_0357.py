# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-12-25 03:57
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('gsm_utility', '0006_gsmusers_mail_sent'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='passwordtoken',
            unique_together=set([('id', 'password_token')]),
        ),
        migrations.AlterUniqueTogether(
            name='sessiontoken',
            unique_together=set([('id', 'session_token')]),
        ),
        migrations.AlterUniqueTogether(
            name='verificationtoken',
            unique_together=set([('id', 'verification_token')]),
        ),
    ]
