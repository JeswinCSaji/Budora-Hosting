# Generated by Django 4.2.4 on 2024-02-20 06:21

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0087_order_deliveryagent'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='order',
            name='deliveryagent',
        ),
        migrations.AddField(
            model_name='orderitem',
            name='deliveryagent',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='user.deliveryagent'),
        ),
    ]
