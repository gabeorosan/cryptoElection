from wtforms import Form, StringField, SubmitField, validators
class EncryptForm(Form):
    msg = StringField('Message', validators=[validators.InputRequired(),
                                             validators.Length(min=9, max=10)])
    A = StringField('A (DHKE)', validators=[validators.InputRequired(),
                                            validators.Length(min=12)])
    encrypt = SubmitField('Encrypt')
