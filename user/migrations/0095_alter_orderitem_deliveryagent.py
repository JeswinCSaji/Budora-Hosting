# Generated by Django 4.2.4 on 2024-03-07 04:12

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0094_orderitem_delivery_choice'),
    ]

    operations = [
        migrations.AlterField(
            model_name='orderitem',
            name='deliveryagent',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='user.deliveryagent'),
        ),
    ]
