# forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser

class RegisterForm(UserCreationForm):

    class Meta:
        model  = CustomUser
        fields = [
            'first_name','last_name','username','email','phone_number',
            'password1','password2',
            # address fields are declared above, so not listed here
        ]

    def save(self, commit=True):
        # 1) save the user
        user = super().save(commit=commit)

        if commit:
            user.save()

        return user

class ProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = [ 'username', 'first_name', 'last_name', 'email', 'phone_number', ]

class ReferralPayoutForm(forms.Form):
    full_name = forms.CharField(max_length=200, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Full Name'}))
    bank_name = forms.CharField(max_length=200, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Bank Name'}))
    account_number = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Account Number'}))
    amount = forms.DecimalField(max_digits=10, decimal_places=2, widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Amount'}))

    def clean_amount(self):
        amount = self.cleaned_data.get('amount')
        if amount <= 0:
            raise forms.ValidationError("Amount must be greater than zero.")
        return amount
        