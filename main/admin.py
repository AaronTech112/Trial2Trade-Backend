from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import MT5Account, Purchase, RealPropRequest, Payout, CustomUser, ReferralSettings, ReferralEarning, DiscountCode, VerifiedTrader


@admin.register(VerifiedTrader)
class VerifiedTraderAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'account_size', 'prop_account_purchased', 'date_passed', 'interviewed', 'interview_link')
    list_filter = ('interviewed', 'account_size', 'date_passed')
    search_fields = ('full_name', 'prop_account_purchased')


@admin.register(DiscountCode)
class DiscountCodeAdmin(admin.ModelAdmin):
    list_display = ('code', 'percentage', 'is_active', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('code',)


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = (
        'username', 'email', 'first_name', 'last_name', 'is_staff', 'referral_code', 'referred_by'
    )
    list_filter = (
        'is_staff', 'is_active',
    )
    search_fields = (
        'email', 'username', 'first_name', 'last_name', 'referral_code'
    )
    ordering = ('email',)
    fieldsets = UserAdmin.fieldsets + (
        ('Additional Info', {'fields': (
            'phone_number',
        )}),
        ('Referral Info', {'fields': (
            'referral_code',
            'referred_by',
        )}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': (
            'phone_number',
            'referral_code',
            'referred_by',
        )}),
    )


@admin.register(ReferralSettings)
class ReferralSettingsAdmin(admin.ModelAdmin):
    list_display = ('commission_percentage',)
    
    def has_add_permission(self, request):
        # Only allow adding if no instance exists
        if self.model.objects.exists():
            return False
        return super().has_add_permission(request)


@admin.register(ReferralEarning)
class ReferralEarningAdmin(admin.ModelAdmin):
    list_display = ('referrer', 'referred_user', 'amount', 'purchase', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('referrer__username', 'referred_user__username', 'referred_user__email')
    readonly_fields = ('created_at',)


@admin.register(MT5Account)
class MT5AccountAdmin(admin.ModelAdmin):
    list_display = ('login', 'account_size', 'account_type', 'user', 'server', 'status', 'balance', 'equity', 'profit', 'assigned_date')
    list_filter = ('assigned', 'status', 'account_size', 'account_type')
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
    list_display = ('user', 'payout_type', 'amount', 'status', 'paid_date', 'transaction_reference')
    list_filter = ('status', 'payout_type', 'paid_date')
    search_fields = ('user__username', 'user__email', 'transaction_reference', 'wallet_address')
    readonly_fields = ('created_at',)
    
    actions = ['mark_as_processing', 'mark_as_completed', 'mark_as_rejected']
    
    def mark_as_processing(self, request, queryset):
        queryset.update(status='processing')
    mark_as_processing.short_description = "Mark selected payouts as processing"
    
    def mark_as_completed(self, request, queryset):
        from django.utils import timezone
        queryset.update(status='completed', paid_date=timezone.now())
    mark_as_completed.short_description = "Mark selected payouts as completed"
    
    def mark_as_rejected(self, request, queryset):
        queryset.update(status='rejected')
    mark_as_rejected.short_description = "Mark selected payouts as rejected"
