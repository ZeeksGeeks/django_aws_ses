from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_aws_ses', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='AwsSesSettings',
        ),
    ]
