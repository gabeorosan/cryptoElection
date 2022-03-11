from wtforms import Form, StringField, SubmitField, validators
class RegisterForm(Form):
    e_id = StringField('Id (encrypted)')
    A = StringField('A (DHKE)')
    rsapub_n = StringField('n (RSA)')
    rsapub_e = StringField('e (RSA)')
    msgs = StringField()
    register = SubmitField('Register')
