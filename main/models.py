from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class CustomUser(AbstractUser):
    first_name = models.CharField(max_length=20)
    last_name = models.CharField(max_length=20)
    username = models.CharField(max_length=20, unique=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, null=True, unique=True)

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
    
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='mt5_accounts')
    account_size = models.CharField(max_length=10, choices=ACCOUNT_SIZE_CHOICES, default='$5k')
    login = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=200)
    server = models.CharField(max_length=200, blank=True)
    assigned = models.BooleanField(default=False)
    status = models.CharField(max_length=50, choices=ACCOUNT_STATUS_CHOICES, default='available')
    
    # MyFXBook data fields
    balance = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    equity = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    profit = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    drawdown = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    initial_balance = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    last_updated = models.DateTimeField(null=True, blank=True)
    
    assigned_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.login} - {self.account_size} ({self.status})"
    
    def assign_to_user(self, user):
        self.user = user
        self.assigned = True
        self.status = 'active'
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
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='payouts')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    paid_date = models.DateTimeField(null=True, blank=True)
    mt5_account = models.ForeignKey(MT5Account, on_delete=models.SET_NULL, null=True, related_name='payouts')
    transaction_reference = models.CharField(max_length=200, blank=True, null=True)
    payment_method = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"Payout {self.user.username} - {self.amount} - {self.status}"

class Certificate(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='certificates')
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='certificates/')
    issued_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} - {self.user.username}"
