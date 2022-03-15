from wtforms import Form, StringField, SubmitField, validators
class DecryptForm(Form):
    msg = StringField('Ciphertext', validators=[validators.InputRequired(),
                                                validators.Length(min=12)])
    rsapub_n = StringField('n (RSA)', validators=[validators.InputRequired()])
    rsapub_e = StringField('e (RSA)', validators=[validators.InputRequired()])
    decrypt = SubmitField('Decrypt')
