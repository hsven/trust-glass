from django import forms

class LoginForm(forms.Form):
    userName = forms.CharField(label="Username:", max_length=100)
    sessionKey = forms.CharField(label="Session Key:", max_length=100)

class HomepageForm(forms.Form):
    userInput = forms.CharField(label="Input:", max_length=100)