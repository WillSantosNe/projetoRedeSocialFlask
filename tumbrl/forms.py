# Aqui vão estar os formulários do nosso site

from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

from tumbrl.models import User
from wtforms.widgets import TextArea


class FormLogin(FlaskForm):
    email = StringField('Email')
    password = PasswordField('Senha')
    btn = SubmitField('Login')
    remember = BooleanField('Lembrar de mim!')


class FormCreateNewAccount(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    usarname = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired(), Length(6, 25)])
    checkPassword = PasswordField('Confirme a senha', validators=[DataRequired(), Length(6, 25), EqualTo('password')])
    btn = SubmitField('Criar Conta!')

    def validate_email(self, email):
        email_of_user = User.query.filter_by(email=email.data).first()
        if email_of_user:
            return ValidationError('~ email já existe ~')


class FormCreateNewPost(FlaskForm):
    text = StringField('Texto', widget=TextArea(), validators=[DataRequired()])
    photo = FileField('Foto', validators=[DataRequired()])
    btn = SubmitField('Publicar!')



