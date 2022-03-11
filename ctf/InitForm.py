from wtforms import Form, StringField, SubmitField, validators
class InitForm(Form):
    init = SubmitField('Initialize CTF')
