from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class CustomUser(AbstractUser):
    first_name = models.CharField(max_length=20)
    last_name = models.CharField(max_length=20)
    username = models.CharField(max_length=20, unique=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, null=True, unique=True)

    # Email verification fields (simple code-based verification)
    email_verification_code = models.CharField(max_length=6, blank=True, null=True)
    email_verification_expires = models.DateTimeField(blank=True, null=True)
    verification_code = models.CharField(max_length=6, null=True, blank=True)
    verification_code_expires = models.DateTimeField(null=True, blank=True)

    # Password reset fields (code-based reset)
    password_reset_code = models.CharField(max_length=6, blank=True, null=True)
    password_reset_expires = models.DateTimeField(blank=True, null=True)
    
    # Referral fields
    referral_code = models.CharField(max_length=20, unique=True, blank=True, null=True)
    referred_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='referrals')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return f"{self.username} - {self.email}"

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        
class MT5Account(models.Model):
    ACCOUNT_STATUS_CHOICES = (
        ('available', 'Available'),
        ('assigned', 'Assigned'),
        ('active', 'Active'),
        ('breached', 'Breached'),
        ('inactive', 'Inactive'),
    )
    
    ACCOUNT_SIZE_CHOICES = (
        ('$5k', '$5k'),
        ('$10k', '$10k'),
        ('$25k', '$25k'),
        ('$50k', '$50k'),
    )
    
    ACCOUNT_TYPE_CHOICES = (
        ('trial', 'Trial'),
        ('funded_phase_1', 'Funded Phase 1'),
        ('funded_phase_2', 'Funded Phase 2'),
        ('funded_live', 'Live Funded'),
    )
    
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='mt5_accounts')
    account_size = models.CharField(max_length=10, choices=ACCOUNT_SIZE_CHOICES, default='$5k')
    login = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=200)
    server = models.CharField(max_length=200, blank=True)
    assigned = models.BooleanField(default=False)
    status = models.CharField(max_length=50, choices=ACCOUNT_STATUS_CHOICES, default='available')
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPE_CHOICES, default='trial')
    
    # MyFXBook data fields
    balance = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    equity = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    profit = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    drawdown = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    initial_balance = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    last_updated = models.DateTimeField(null=True, blank=True)
    # Daily drawdown tracking
    daily_max_drawdown = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    equity_open_day = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    equity_open_day_date = models.DateField(null=True, blank=True)
    
    assigned_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.login} - {self.account_size} ({self.status})"
    
    def assign_to_user(self, user):
        self.user = user
        self.assigned = True
        self.status = 'active'
        # Ensure newly assigned accounts start as trial type
        if not self.account_type:
            self.account_type = 'trial'
        self.assigned_date = timezone.now()
        self.save()
    
    def check_breach_status(self):
        """Check if account should be marked as breached based on balance"""
        if self.balance and self.initial_balance:
            if self.balance < (self.initial_balance * 0.1):  # 10% rule
                self.status = 'breached'
                self.save()
                return True
        return False


class Purchase(models.Model):
    PAYMENT_STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('successful', 'Successful'),
        ('failed', 'Failed'),
    )
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='purchases')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    tx_ref = models.CharField(max_length=200, unique=True)
    verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    flutterwave_reference = models.CharField(max_length=200, blank=True, null=True)
    account = models.OneToOneField(MT5Account, on_delete=models.SET_NULL, null=True, blank=True, related_name='purchase')

    def __str__(self):
        return f"Purchase {self.tx_ref} - {self.user.username}"


class RealPropRequest(models.Model):
    REQUEST_TYPE_CHOICES = (
        ('real_account', 'Real Account'),
        ('phase_2', 'Phase 2'),
        ('payout', 'Payout'),
    )
    
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='prop_requests')
    request_type = models.CharField(max_length=20, choices=REQUEST_TYPE_CHOICES, default='real_account')
    phase = models.IntegerField(default=1)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    response_message = models.TextField(blank=True, null=True)
    mt5_account = models.ForeignKey(MT5Account, on_delete=models.SET_NULL, null=True, blank=True, related_name='prop_requests')

    def __str__(self):
        return f"{self.request_type} - {self.user.username} - {self.status}"


class Payout(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('rejected', 'Rejected'),
    )

    PAYOUT_TYPE_CHOICES = (
        ('trading', 'Trading Account'),
        ('referral', 'Referral Commission'),
    )
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='payouts')
    payout_type = models.CharField(max_length=20, choices=PAYOUT_TYPE_CHOICES, default='trading')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    paid_date = models.DateTimeField(null=True, blank=True)
    mt5_account = models.ForeignKey(MT5Account, on_delete=models.SET_NULL, null=True, blank=True, related_name='payouts')
    transaction_reference = models.CharField(max_length=200, blank=True, null=True)
    payment_method = models.CharField(max_length=100, blank=True, null=True)
    
    # Generic bank details text
    bank_details = models.TextField(blank=True, null=True)
    
    # Specific fields for Referral Payouts
    full_name = models.CharField(max_length=200, blank=True, null=True)
    bank_name = models.CharField(max_length=200, blank=True, null=True)
    account_number = models.CharField(max_length=100, blank=True, null=True)
    
    wallet_address = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return f"Payout ({self.payout_type}) {self.user.username} - {self.amount} - {self.status}"

class Certificate(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='certificates')
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='certificates/')
    issued_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} - {self.user.username}"

class Announcement(models.Model):
    title = models.CharField(max_length=200)
    body = models.TextField()
    image = models.FileField(upload_to='announcements/', blank=True, null=True)
    is_published = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    link_text = models.CharField(max_length=100, blank=True, null=True)
    link_url = models.CharField(max_length=300, blank=True, null=True)

    def __str__(self):
        return self.title

class GlobalAlert(models.Model):
    SEVERITY_CHOICES = (
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('danger', 'Danger'),
        ('success', 'Success'),
    )
    message = models.CharField(max_length=300)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='info')
    is_active = models.BooleanField(default=False)
    link_url = models.CharField(max_length=300, blank=True, null=True)
    link_text = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.message

class ReferralSettings(models.Model):
    commission_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=10.00, help_text="Commission percentage for referrals (e.g., 10.00 for 10%)")

    def save(self, *args, **kwargs):
        if not self.pk and ReferralSettings.objects.exists():
            return
        return super(ReferralSettings, self).save(*args, **kwargs)

    def __str__(self):
        return f"Referral Settings ({self.commission_percentage}%)"

    class Meta:
        verbose_name = "Referral Settings"
        verbose_name_plural = "Referral Settings"

class ReferralEarning(models.Model):
    referrer = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='referral_earnings')
    referred_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='generated_earnings')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    purchase = models.ForeignKey(Purchase, on_delete=models.CASCADE, related_name='referral_earnings')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.referrer.username} earned {self.amount} from {self.referred_user.username}"

class DiscountCode(models.Model):
    code = models.CharField(max_length=50, unique=True)
    percentage = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.code

class VerifiedTrader(models.Model):
    full_name = models.CharField(max_length=200)
    date_passed = models.DateField()
    account_size = models.CharField(max_length=20)
    prop_account_purchased = models.CharField(max_length=100)
    interviewed = models.BooleanField(default=False)
    interview_link = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.account_size}"
