# Generated by Django 4.2.4 on 2024-01-25 06:27

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('user', '0059_userprofile_latitude_userprofile_longitude'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserSellerDistance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('distance', models.FloatField()),
                ('seller', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.seller')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
