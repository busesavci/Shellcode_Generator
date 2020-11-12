from django import forms
from .models import PAYLOAD_TYPE, APPLICATION_TYPE, ENCRYPTION_TYPE


class EncryptForm(forms.Form):
    IP_value = forms.CharField(label='IP', )
    Port_value = forms.IntegerField(label='Port')
    Sleep_value = forms.IntegerField(label='Sleep')
    Payload_value = forms.ChoiceField(choices=PAYLOAD_TYPE, label='Payload')
    Application_value = forms.ChoiceField(choices=APPLICATION_TYPE, label='Type')
    Encryption_value = forms.ChoiceField(choices=ENCRYPTION_TYPE, label='Encryption')
