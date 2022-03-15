from wtforms import Form, StringField, SubmitField, validators
class CreateForm(Form):
    name = StringField('Name', [validators.InputRequired()])
    create = SubmitField('Create')
