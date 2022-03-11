from wtforms import Form, StringField, SubmitField, validators
class VoteForm(Form):
    e_vn = StringField('Validation Number')
    candidate = StringField('Candidate')
    A = StringField('A (DHKE)')
    n = StringField('n (RSA)')
    e = StringField('e (RSA)')
    castvote = SubmitField('Cast Vote')
