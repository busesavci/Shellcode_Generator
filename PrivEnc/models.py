from django.db import models

PAYLOAD_TYPE = (
    ('meterpreter/reverse_tcp', 'meterpreter/reverse_tcp'),
    ('meterpreter/x64/reverse_tcp', 'meterpreter/x64/reverse_tcp'),
    ('meterpreter/bind_tcp', 'meterpreter/bind_tcp'),
    ('meterpreter/x64/bind_tcp', 'meterpreter/x64/bind_tcp'),
)

APPLICATION_TYPE = (
    ('Console Application', 'Console Application'),
    ('Windows Form Application', 'Windows Form Application'),
)

ENCRYPTION_TYPE = (
    ('RSA', 'RSA'),
    ('AES-CBC', 'AES-CBC'),
    ('Blowfish', 'Blowfish'),
)


class Data(models.Model):
    IP_value = models.CharField(default='0.0.0.0', max_length=15, null=True)
    Port_value = models.IntegerField(default=4444, null=True)
    Sleep_value = models.IntegerField(default=0, null=True)
    Application_value = models.CharField(default='Console Application', choices=APPLICATION_TYPE, max_length=50, null=True)
    Payload_value = models.CharField(default='meterpreter/reverse_tcp', choices=PAYLOAD_TYPE, max_length=50, null=True)
    Encryption_value = models.CharField(default='RSA', choices=ENCRYPTION_TYPE, max_length=50, null=True)

    def __str__(self):

        return 'IP : %s, Port : %s, Type: %s, Payload : %s, Encryption: %s' % (
            self.IP_value,
            self.Port_value,
            self.Application_value,
            self.Payload_value,
            self.Encryption_value,
        )
