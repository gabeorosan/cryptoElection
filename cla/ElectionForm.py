from wtforms import Form, IntegerField, SubmitField, validators
class ElectionForm(Form):
    timelength = IntegerField('Time Length (mins)')
    startelection = SubmitField('Start election')

