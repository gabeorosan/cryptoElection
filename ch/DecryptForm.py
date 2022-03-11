from wtforms import Form, StringField, SubmitField, validators
class DecryptForm(Form):
    msg = StringField('Ciphertext')
    rsapub_n = StringField('n (RSA)')
    rsapub_e = StringField('e (RSA)')
    decrypt = SubmitField('Decrypt')