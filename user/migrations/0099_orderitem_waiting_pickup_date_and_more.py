# Generated by Django 4.2.4 on 2024-03-30 10:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0098_orderitem_order_not_valid'),
    ]

    operations = [
        migrations.AddField(
            model_name='orderitem',
            name='waiting_pickup_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
