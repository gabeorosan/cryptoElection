from wtforms import Form, StringField, SubmitField, validators
class VoteForm(Form):
    e_vn = StringField('Validation Number (Encrypted)', validators=[validators.InputRequired(),
                                                                    validators.Length(min=12)])
    candidate = StringField('Candidate', validators=[validators.InputRequired()])
    A = StringField('A (DHKE)', validators=[validators.InputRequired(),
                                            validators.Length(min=12)])
    n = StringField('n (RSA)', validators=[validators.InputRequired(),
                                            validators.Length(min=12)])
    e = StringField('e (RSA)', validators=[validators.InputRequired()])
    castvote = SubmitField('Cast Vote')
