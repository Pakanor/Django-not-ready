from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from .models import *
from django.core.validators import validate_email
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.hashers import check_password
from .models import Task


class registration_form(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        try:
            validate_email(email)
            if User.objects.filter(email=email).exists():
                raise ValidationError("Email jest już zajęty.")
        except ValidationError:
            raise ValidationError("Wprowadzony adres e-mail jest niepoprawny.")

        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        user.is_active = False
        if commit:
            user.save()
        return user


class login_form(forms.Form):
    username = forms.CharField(label='Login')
    password = forms.CharField(label='haslo', widget=forms.PasswordInput)

    def clean_username(self):
        username = self.cleaned_data.get('username')
        try:
            user = User.objects.get(username=username)
            if not user.is_active:
                print("nieaktywny")
                raise ValidationError("niekatyny uzytkownik")
            else:
                return username

        except User.DoesNotExist:
            print("tu2")
            raise ValidationError("nie ma takiego uzytkownika")


class add_task(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['title', 'description']


class edit_task(forms.ModelForm):
    class Meta:
        model = Task
        fields = ['title', 'description']
