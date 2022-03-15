from wtforms import Form, StringField, SubmitField, validators
class RegisterForm(Form):
    e_id = StringField('Id (encrypted)', validators=[validators.InputRequired(),
                                                    validators.Length(min=12)])
    A = StringField('A (DHKE)', validators=[validators.InputRequired(),
                                            validators.Length(min=12)])
    rsapub_n = StringField('n (RSA)', validators=[validators.InputRequired(),
                                                    validators.Length(min=12)])
    rsapub_e = StringField('e (RSA)', validators=[validators.InputRequired()])
    register = SubmitField('Register')
