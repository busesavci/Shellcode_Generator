# Generated by Django 3.1.1 on 2020-09-21 13:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('PrivEnc', '0006_auto_20200921_1627'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Choice',
        ),
        migrations.DeleteModel(
            name='Question',
        ),
    ]