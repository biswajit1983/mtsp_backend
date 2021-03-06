# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-12-23 22:38
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('gsm_utility', '0003_auto_20171220_1055'),
    ]

    operations = [
        migrations.CreateModel(
            name='SessionToken',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('salt', models.CharField(max_length=255, unique=True)),
                ('session_token', models.CharField(max_length=255, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('valid_for', models.IntegerField()),
                ('valid', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'sessiontokens',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='VerificationToken',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('salt', models.CharField(max_length=255, unique=True)),
                ('verification_token', models.CharField(max_length=255, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('valid_for', models.IntegerField()),
                ('valid', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'verificationtokens',
                'managed': True,
            },
        ),
        migrations.RenameField(
            model_name='feedback',
            old_name='future_trading_experience',
            new_name='futures_trading_experience',
        ),
        migrations.AddField(
            model_name='feedback',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
        migrations.AddField(
            model_name='feedback',
            name='updated_at',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
        migrations.AddField(
            model_name='gsmusers',
            name='city',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='gsmusers',
            name='house_number',
            field=models.CharField(blank=True, max_length=10),
        ),
        migrations.AddField(
            model_name='gsmusers',
            name='postcode',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='gsmusers',
            name='street',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='gsmusers',
            name='verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='verificationtoken',
            name='gsm_user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='gsm_utility.GSMUsers'),
        ),
        migrations.AddField(
            model_name='sessiontoken',
            name='gsm_user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='gsm_utility.GSMUsers'),
        ),
    ]
