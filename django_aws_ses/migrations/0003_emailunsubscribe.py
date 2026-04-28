from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('django_aws_ses', '0002_remove_awssessettings'),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailUnsubscribe',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(db_index=True, max_length=254, unique=True)),
                ('unsubscribed', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'Email Unsubscribe',
                'verbose_name_plural': 'Email Unsubscribes',
            },
        ),
    ]
