from django.db import migrations


def remove_awssessettings_if_exists(apps, schema_editor):
    """Remove AwsSesSettings model only if it exists."""
    try:
        AwsSesSettings = apps.get_model('django_aws_ses', 'AwsSesSettings')
        # If we get here, the model exists, so we can delete it
        return True
    except LookupError:
        # Model doesn't exist, skip deletion
        return False


class Migration(migrations.Migration):

    dependencies = [
        ('django_aws_ses', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(
            code=lambda apps, schema_editor: None,
            reverse_code=lambda apps, schema_editor: None,
        ),
        migrations.DeleteModel(
            name='AwsSesSettings',
        ),
    ]
