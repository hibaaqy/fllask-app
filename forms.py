import re

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import IntegerField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Regexp, ValidationError


SUSPICIOUS_PATTERNS = [
    r"--",
    r";",
    r"/\*",
    r"\*/",
    r"\bselect\b",
    r"\binsert\b",
    r"\bupdate\b",
    r"\bdelete\b",
    r"\bdrop\b",
    r"\bunion\b",
    r"<script",
    r"</script>",
    r"javascript:",
]


def reject_malicious_input(form, field):
    value = (field.data or "").strip().lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, value):
            raise ValidationError("Invalid or suspicious input detected.")


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=2, max=20),
            Regexp(r"^[A-Za-z0-9_]+$", message="Username must contain only letters, numbers, or underscores"),
        ],
    )
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, max=64),
            Regexp(
                r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&]).+$",
                message="Password must include letters, numbers, and one special character.",
            ),
        ],
    )
    submit = SubmitField("Sign Up")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=64)])
    submit = SubmitField("Login")


class StudentForm(FlaskForm):
    fname = StringField(
        "First Name",
        validators=[
            DataRequired(),
            Length(min=2, max=50),
            Regexp(r"^[A-Za-z ]+$", message="Only letters and spaces are allowed."),
            reject_malicious_input,
        ],
    )
    lname = StringField(
        "Last Name",
        validators=[
            DataRequired(),
            Length(min=2, max=50),
            Regexp(r"^[A-Za-z ]+$", message="Only letters and spaces are allowed."),
            reject_malicious_input,
        ],
    )
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    city = StringField(
        "City",
        validators=[
            DataRequired(),
            Length(min=2, max=50),
            Regexp(r"^[A-Za-z ]+$", message="Only letters and spaces are allowed."),
            reject_malicious_input,
        ],
    )
    age = IntegerField(
        "Age",
        validators=[DataRequired(), NumberRange(min=16, max=100, message="Enter a valid age.")],
    )
    submit = SubmitField("Save Record")


class ContactForm(FlaskForm):
    full_name = StringField(
        "Full Name",
        validators=[
            DataRequired(),
            Length(min=3, max=100),
            Regexp(r"^[A-Za-z ]+$", message="Only letters and spaces are allowed."),
            reject_malicious_input,
        ],
    )
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    phone = StringField(
        "Phone Number",
        validators=[DataRequired(), Regexp(r"^[0-9+() ]{7,20}$", message="Enter a valid phone number.")],
    )
    subject = StringField("Subject", validators=[DataRequired(), Length(min=3, max=120), reject_malicious_input])
    message = TextAreaField("Message", validators=[DataRequired(), Length(min=10, max=500), reject_malicious_input])
    submit = SubmitField("Submit Contact Form")


class FileUploadForm(FlaskForm):
    file = FileField(
        "Choose File",
        validators=[
            FileRequired(message="Please choose a file."),
            FileAllowed(["png", "jpg", "jpeg", "pdf"], message="Only PNG, JPG, JPEG, and PDF files are allowed."),
        ],
    )
    submit = SubmitField("Upload Securely")