# Generated by Django 4.2.4 on 2024-01-29 03:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0064_alter_certification_latitude_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='certification',
            name='latitude',
            field=models.DecimalField(decimal_places=15, default=0.0, max_digits=20),
        ),
        migrations.AlterField(
            model_name='certification',
            name='longitude',
            field=models.DecimalField(decimal_places=15, default=0.0, max_digits=20),
        ),
    ]
