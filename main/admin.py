from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import MT5Account, Purchase, RealPropRequest, Payout, CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = (
        'username', 'email', 'first_name', 'last_name', 'is_staff',
    )
    list_filter = (
        'is_staff', 'is_active',
    )
    search_fields = (
        'email', 'username', 'first_name', 'last_name',
    )
    ordering = ('email',)
    fieldsets = UserAdmin.fieldsets + (
        ('Additional Info', {'fields': (
            'phone_number',
        )}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': (
            'phone_number',
        )}),
    )


@admin.register(MT5Account)
class MT5AccountAdmin(admin.ModelAdmin):
    list_display = ('login', 'account_size', 'user', 'server', 'status', 'balance', 'equity', 'profit', 'assigned_date')
    list_filter = ('assigned', 'status', 'account_size')
    search_fields = ('login', 'user__username', 'user__email')
    readonly_fields = ('last_updated',)
    
    actions = ['mark_as_active', 'mark_as_breached']
    
    def mark_as_active(self, request, queryset):
        queryset.update(status='active')
    mark_as_active.short_description = "Mark selected accounts as active"
    
    def mark_as_breached(self, request, queryset):
        queryset.update(status='breached')
    mark_as_breached.short_description = "Mark selected accounts as breached"


@admin.register(Purchase)
class PurchaseAdmin(admin.ModelAdmin):
    list_display = ('tx_ref', 'user', 'amount', 'payment_status', 'verified', 'created_at', 'account')
    list_filter = ('verified', 'payment_status')
    search_fields = ('tx_ref', 'user__username', 'user__email', 'flutterwave_reference')
    readonly_fields = ('created_at',)


@admin.register(RealPropRequest)
class RealPropRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'request_type', 'status', 'mt5_account', 'created_at')
    list_filter = ('status', 'request_type')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('created_at',)
    
    actions = ['approve_request', 'reject_request']
    
    def approve_request(self, request, queryset):
        queryset.update(status='approved')
    approve_request.short_description = "Approve selected requests"
    
    def reject_request(self, request, queryset):
        queryset.update(status='rejected')
    reject_request.short_description = "Reject selected requests"


@admin.register(Payout)
class PayoutAdmin(admin.ModelAdmin):
    list_display = ('user', 'amount', 'status', 'mt5_account', 'created_at', 'paid_date')
    list_filter = ('status',)
    search_fields = ('user__username', 'user__email', 'transaction_reference')
    readonly_fields = ('created_at',)
    
    actions = ['mark_as_completed', 'mark_as_processing', 'mark_as_rejected']
    
    def mark_as_completed(self, request, queryset):
        from django.utils import timezone
        queryset.update(status='completed', paid_date=timezone.now())
    mark_as_completed.short_description = "Mark selected payouts as completed"
    
    def mark_as_processing(self, request, queryset):
        queryset.update(status='processing')
    mark_as_processing.short_description = "Mark selected payouts as processing"
    
    def mark_as_rejected(self, request, queryset):
        queryset.update(status='rejected')
    mark_as_rejected.short_description = "Mark selected payouts as rejected"
