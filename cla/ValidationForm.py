from wtforms import Form, StringField, SubmitField, validators
class ValidationForm(Form):
    e_id = StringField('Id (encrypted)')
    B = StringField('A (DHKE)')
    rsapub_n = StringField('n (RSA)')
    rsapub_e = StringField('e (RSA)')
    getvalidation = SubmitField('Register')
