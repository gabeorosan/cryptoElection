from wtforms import Form, StringField, validators
class KeyExchangeForm(Form):
    name = StringField('Name')