from django.db import migrations


def check_and_remove_model(apps, schema_editor):
    """Only remove model if it exists in the current state."""
    pass  # This is handled by the conditional DeleteModel below


class Migration(migrations.Migration):

    dependencies = [
        ('django_aws_ses', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL(
            "DROP TABLE IF EXISTS django_aws_ses_awssessettings;",
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]

    def apply(self, project_state, schema_editor, collect_sql=False):
        # Check if AwsSesSettings exists in the state before trying to delete it
        try:
            project_state.models[('django_aws_ses', 'awssessettings')]
            # Model exists in state, add DeleteModel operation
            self.operations.insert(0, migrations.DeleteModel(name='AwsSesSettings'))
        except KeyError:
            # Model doesn't exist in state, skip DeleteModel
            pass
        
        return super().apply(project_state, schema_editor, collect_sql)
