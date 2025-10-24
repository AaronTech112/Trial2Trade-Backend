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
        