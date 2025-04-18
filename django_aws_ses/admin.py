from django.contrib import admin
from .models import (
    AwsSesSettings,
    SESStat,
    BounceRecord,
    AwsSesUserAddon,
    ComplaintRecord,
    SendRecord,
    UnknownRecord,
    BlackListedDomains,
)


class AdminEmailListFilter(admin.SimpleListFilter):
    """Filter records by email address containing a search term."""
    title = 'email'
    parameter_name = 'email'

    def lookups(self, request, model_admin):
        return (
            (None, 'All'),
        )

    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(email__icontains=self.value())
        return queryset


@admin.register(AwsSesSettings)
class AwsSesSettingsAdmin(admin.ModelAdmin):
    """Admin interface for AWS SES settings."""
    model = AwsSesSettings
    list_display = ('get_site', 'region_name')
    list_display_links = ('get_site',)
    search_fields = ('site__domain', 'region_name')

    def get_site(self, obj):
        """Display the domain of the associated site."""
        return obj.site.domain

    get_site.short_description = 'Domain'
    get_site.admin_order_field = 'site__domain'


@admin.register(AwsSesUserAddon)
class AwsSesUserAddonAdmin(admin.ModelAdmin):
    """Admin interface for user-specific AWS SES settings."""
    model = AwsSesUserAddon
    list_display = ('get_email', 'unsubscribe')
    list_display_links = ('get_email',)
    list_filter = ('unsubscribe',)
    search_fields = ('user__email',)

    def get_email(self, obj):
        """Display the user's email address."""
        return obj.user.email

    get_email.short_description = 'Email'
    get_email.admin_order_field = 'user__email'


@admin.register(SESStat)
class SESStatAdmin(admin.ModelAdmin):
    """Admin interface for SES statistics."""
    model = SESStat
    list_display = ('date', 'delivery_attempts', 'bounces', 'complaints', 'rejects')
    list_display_links = ('date',)
    date_hierarchy = 'date'
    ordering = ('-date',)


@admin.register(BounceRecord)
class BounceRecordAdmin(admin.ModelAdmin):
    """Admin interface for bounce records."""
    model = BounceRecord
    list_display = ('email', 'bounce_type', 'bounce_sub_type', 'status', 'timestamp')
    list_display_links = ('email',)
    list_filter = (AdminEmailListFilter, 'bounce_type', 'bounce_sub_type', 'status', 'timestamp')
    search_fields = ('email', 'diagnostic_code')
    date_hierarchy = 'timestamp'


@admin.register(ComplaintRecord)
class ComplaintRecordAdmin(admin.ModelAdmin):
    """Admin interface for complaint records."""
    model = ComplaintRecord
    list_display = ('email', 'sub_type', 'feedback_type', 'timestamp')
    list_display_links = ('email',)
    list_filter = (AdminEmailListFilter, 'sub_type', 'feedback_type', 'timestamp')
    search_fields = ('email',)
    date_hierarchy = 'timestamp'


@admin.register(SendRecord)
class SendRecordAdmin(admin.ModelAdmin):
    """Admin interface for send records."""
    model = SendRecord
    list_display = ('source', 'destination', 'subject', 'timestamp', 'status')
    list_display_links = ('destination',)
    list_filter = (AdminEmailListFilter, 'source', 'status', 'timestamp')
    search_fields = ('source', 'destination', 'subject')
    date_hierarchy = 'timestamp'


@admin.register(UnknownRecord)
class UnknownRecordAdmin(admin.ModelAdmin):
    """Admin interface for unknown SES event records."""
    model = UnknownRecord
    list_display = ('event_type', 'timestamp')
    list_display_links = ('event_type',)
    list_filter = ('event_type', 'timestamp')
    search_fields = ('event_type', 'aws_data')
    date_hierarchy = 'timestamp'


@admin.register(BlackListedDomains)
class BlackListedDomainsAdmin(admin.ModelAdmin):
    """Admin interface for blacklisted domains."""
    model = BlackListedDomains
    list_display = ('domain', 'timestamp')
    list_display_links = ('domain',)
    list_filter = ('timestamp',)
    search_fields = ('domain',)
    date_hierarchy = 'timestamp'