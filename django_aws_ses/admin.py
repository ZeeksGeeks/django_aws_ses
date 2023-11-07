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

from . import settings

#logger = settings.logger

class AwsSesSettingsAdmin(admin.ModelAdmin):
    model = AwsSesSettings
    list_display = ('get_site', 'region_name')
    
    def get_site(self, obj):
        return obj.site.domain 
    
    get_site.short_description = 'domain'
    get_site.admin_order_field = 'site__domain'
    
admin.site.register(AwsSesSettings, AwsSesSettingsAdmin)

class AwsSesUserAddonAdmin(admin.ModelAdmin):
    model = AwsSesUserAddon
    list_display = ('get_email', 'unsubscribe')
    def get_email(self, obj):
        return obj.user.email
    
    get_email.short_description = 'email'
    get_email.admin_order_field = 'user__email'
    
admin.site.register(AwsSesUserAddon, AwsSesUserAddonAdmin)

class SESStatAdmin(admin.ModelAdmin):
    model = SESStat
    list_display = ('date', 'delivery_attempts', 'bounces', 'complaints', 'rejects')
    
admin.site.register(SESStat, SESStatAdmin)

class AdminEmailListFilter(admin.SimpleListFilter):
    def queryset(self, request, queryset):
        #logger.info('self.value(): %s' % self.value())
        return queryset.filter(email__contains=self.value())
                               
class BounceRecordAdmin(admin.ModelAdmin):
    model = BounceRecord
    list_display = ('email', 'bounce_type', 'bounce_sub_type', 'status', 'timestamp')
    list_filter = ('email', 'bounce_type', 'bounce_sub_type', 'status', 'timestamp')

admin.site.register(BounceRecord, BounceRecordAdmin)

class ComplaintRecordAdmin(admin.ModelAdmin):
    model = ComplaintRecord
    list_display = ('email', 'sub_type', 'feedback_type', 'timestamp')
    list_filter = ('email', 'sub_type', 'feedback_type', 'timestamp')

admin.site.register(ComplaintRecord, ComplaintRecordAdmin)

class SendRecordAdmin(admin.ModelAdmin):
    model = SendRecord
    list_display = ('source', 'destination', 'subject', 'timestamp', 'status')
    list_filter = ('source', 'destination', 'subject', 'timestamp', 'status')

admin.site.register(SendRecord, SendRecordAdmin)

class UnknownRecordAdmin(admin.ModelAdmin):
    model = UnknownRecord
    list_display = ('event_type', 'aws_data')
    list_filter = ('event_type', 'aws_data')

admin.site.register(UnknownRecord, UnknownRecordAdmin)

class BlackListedDomainsAdmin(admin.ModelAdmin):
    model = BlackListedDomains
    list_display = ('domain', 'timestamp')
    list_filter = ('domain', 'timestamp')

admin.site.register(BlackListedDomains, BlackListedDomainsAdmin)