# Generated by Django 4.2.4 on 2024-01-29 06:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0070_userprofile_latitude_userprofile_longitude'),
    ]

    operations = [
        migrations.AddField(
            model_name='seller',
            name='avgrating',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]
