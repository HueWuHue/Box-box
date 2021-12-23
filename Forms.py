from wtforms import Form, StringField, TextAreaField, DecimalField, validators, IntegerField, BooleanField, SubmitField, \
    SelectField, PasswordField, RadioField, FileField
from wtforms.validators import DataRequired, Length, Email, Regexp, ValidationError
from flask_wtf import FlaskForm, RecaptchaField  # New


# User related
class LoginForm(Form):
    Email = StringField("Email", [validators.DataRequired()])
    Password = PasswordField("Password", [validators.DataRequired()])
    Workgroup = StringField("Workgroup", [validators.DataRequired()])
    # recaptcha = RecaptchaField()  # New


class OTPForm(Form):
    OTP = StringField("OTP", [validators.DataRequired(), validators.Length(min=6, max=6)])


class ChangePasswordForm(Form):
    Password = PasswordField("New Password", [validators.DataRequired(), validators.Length(min=8)])
    Confirm = PasswordField("Confirm Password", [validators.DataRequired(), validators.EqualTo("Password")])

    def validate_Password(form, field):
        lower = False
        upper = False
        num = False
        spchar = False
        for char in field.data:
            if char in 'abcdefghijklmnopqrstuvwxyz':
                lower = True
            elif char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                upper = True
            elif char in '1234567890':
                num = True
            else:
                spchar = True
        if not (lower and upper and num and spchar):
            raise ValidationError(
                'Password should have a combination of uppercase and lower case letters,numbers and special characters.')


# File related
class UploadForm(Form):
    File = FileField('Upload')
    Class = SelectField("Classification", [validators.DataRequired()],
                        choices=[('', 'Select'), ('Unclassified', 'Unclassified'), ('Confidential', 'Confidential'),
                                 ('Secret', 'Secret'), ('Top Secret', 'Top Secret')])


class BatchUploadForm(Form):
    Files = FileField('Upload')


class EditForm(Form):
    Class = SelectField("Classification", [validators.DataRequired()],
                        choices=[('', 'Select'), ('Unclassified', 'Unclassified'), ('Confidential', 'Confidential'),
                                 ('Secret', 'Secret'), ('Top Secret', 'Top Secret')])


class ShareForm(Form):
    Email = StringField("Email", [validators.DataRequired()])
    FileId = StringField('File ID',[validators.DataRequired()])
