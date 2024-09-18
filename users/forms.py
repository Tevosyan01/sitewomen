from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm


class LoginUserForm(AuthenticationForm):
    username = forms.CharField(label="Логин", widget=forms.TextInput(attrs={'class': 'form-input'}))
    password = forms.CharField(label="Пароль", widget=forms.PasswordInput(attrs={'class': 'form-input'}))


class RegisterUserForm(forms.ModelForm):
    username = forms.CharField(label="Логин")
    password = forms.CharField(label="Пароль", widget=forms.PasswordInput())
    password_confirm = forms.CharField(label="Подтверждение пароля", widget=forms.PasswordInput())

    class Meta:
        model = get_user_model()
        fields = ['username','email','first_name','last_name', 'password', 'password_confirm']
        labels = {
            'email':'Email',
            'first_name':'Имя',
            'last_name':'Фамилия',
        }

    def clean_password2(self):
        cd = self.cleaned_data
        if cd['password']!= cd['password_confirm']:
            raise forms.ValidationError('Пароли не совпадают.')


    def clean_email(self):
        email = self.cleaned_data['email']
        if get_user_model().objects.filter(email=email).exists():
            raise forms.ValidationError('Пользователь с таким email уже зарегистрирован.')
        return email


class ProfileUserForm(forms.ModelForm):
    username = forms.CharField(disabled=True, label='Логин',widget=forms.TextInput(attrs={'class': 'form-input'}))
    email = forms.CharField(disabled=True, label='Email',widget=forms.TextInput(attrs={'class': 'form-input'}))

    class Meta:
        model = get_user_model()
        fields = ['username', 'email','first_name', 'last_name']
        labels = {
            'first_name':'Имя',
            'last_name':'Фамилия',
        }
        widgets ={
            'first_name': forms.TextInput(attrs={'class': 'form-input'}),
            'last_name': forms.TextInput(attrs={'class': 'form-input'}),
        }

class UserPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(label="Старый пароль", widget=forms.PasswordInput(attrs={'class': 'form-input'}))
    new_password1 = forms.CharField(label="Новый пароль", widget=forms.PasswordInput(attrs={'class': 'form-input'}))
    new_password2 = forms.CharField(label="Подтверждение нового пароля", widget=forms.PasswordInput(attrs={'class': 'form-input'}))
