from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('django_aws_ses', '0001_initial'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.DeleteModel(name='AwsSesSettings'),
            ],
            database_operations=[
                migrations.RunSQL(
                    "DROP TABLE IF EXISTS django_aws_ses_awssessettings;",
                    reverse_sql=migrations.RunSQL.noop,
                ),
            ],
        ),
    ]
