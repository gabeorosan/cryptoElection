from wtforms import Form, StringField, SubmitField, validators
class CreateForm(Form):
    name = StringField('Name', [validators.Length(min=3, max=30)])
    create = SubmitField('Create')
