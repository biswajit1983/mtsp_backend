# Generated by Django 2.0.1 on 2018-01-25 16:21

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gsm_utility', '0017_auto_20180125_0608'),
    ]

    operations = [
        migrations.CreateModel(
            name='SignalsData',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('csiSym', models.CharField(max_length=4)),
                ('date', models.IntegerField()),
                ('riskOn', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('riskOff', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('prev1', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('antiPrev1', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('prev5', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('lowEq', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('highEq', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('antiHighEq', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('anti50', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('sea', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
                ('antiSea', models.IntegerField(default=0, validators=[django.core.validators.MaxValueValidator(1), django.core.validators.MinValueValidator(-1)])),
            ],
        ),
        migrations.AlterField(
            model_name='feedback',
            name='FX_trading_experience',
            field=models.CharField(choices=[('a', '0 years'), ('b', '1 years'), ('c', '1-2 years'), ('d', '2-5 years'), ('e', '5 years+')], default='a', max_length=1),
        ),
        migrations.AlterField(
            model_name='feedback',
            name='bond_trading_experience',
            field=models.CharField(choices=[('a', '0 years'), ('b', '1 years'), ('c', '1-2 years'), ('d', '2-5 years'), ('e', '5 years+')], default='a', max_length=1),
        ),
        migrations.AlterField(
            model_name='feedback',
            name='futures_trading_experience',
            field=models.CharField(choices=[('a', '0 years'), ('b', '1 years'), ('c', '1-2 years'), ('d', '2-5 years'), ('e', '5 years+')], default='a', max_length=1),
        ),
        migrations.AlterField(
            model_name='feedback',
            name='risk_assets',
            field=models.CharField(choices=[('a', '$0 - $20,000'), ('b', '$20,000 - $40,000'), ('c', '$40,000 - $80,000'), ('d', '$80,000 - $120,000'), ('e', '$120,000+')], default='a', max_length=1),
        ),
        migrations.AlterField(
            model_name='feedback',
            name='stock_trading_experience',
            field=models.CharField(choices=[('a', '0 years'), ('b', '1 years'), ('c', '1-2 years'), ('d', '2-5 years'), ('e', '5 years+')], default='a', max_length=1),
        ),
    ]
