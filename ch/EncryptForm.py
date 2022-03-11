from wtforms import Form, StringField, SubmitField, validators
class EncryptForm(Form):
    msg = StringField('Message')
    A = StringField('A (DHKE)')
    encrypt = SubmitField('Encrypt')