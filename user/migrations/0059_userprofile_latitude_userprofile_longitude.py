# Generated by Django 4.2.4 on 2024-01-24 04:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0058_seller_latitude_seller_longitude'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='latitude',
            field=models.CharField(blank=True, max_length=12, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='longitude',
            field=models.CharField(blank=True, max_length=12, null=True),
        ),
    ]
