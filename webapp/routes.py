from flask import render_template, flash, redirect, url_for
from webapp import app
from webapp.forms import LoginForm
from flask_login import current_user, login_user
from webapp.models import User
from flask_login import logout_user
from flask_login import login_required
from flask import request
from werkzeug.urls import url_parse
from webapp import wappdb
from webapp.forms import RegistrationForm, EditProfileForm, ResetPasswordRequestForm, ResetPasswordForm, StartStop
from email.message import EmailMessage
import threading
import smtplib


def send_async_email(app_, srv, msge):
    with app_.app_context():
        if not srv['SSL']:
            smtp = smtplib.SMTP(srv['server'], srv['port'])
            smtp.starttls()
        else:
            smtp = smtplib.SMTP_SSL(srv['server'], srv['port'])  # Use this for Nemaris Server
        smtp.login(srv['user'], srv['password'])
        smtp.sendmail(msge['From'], msge['To'], msge.as_string())
        smtp.quit()


def send_email(server, msg):
    threading.Thread(target=send_async_email, args=(app, server, msg)).start()


def send_password_reset_email(usr):
    smtpserver = app.config['SMTP']

    msg = EmailMessage()
    msg['Subject'] = "Restablecer Password - Robot Email"
    msg['From'] = smtpserver['user']
    msg['To'] = usr.email
    msg.set_type('text/html')

    token = usr.get_reset_password_token()
    msg.set_content(render_template('email/reset_password.txt', user=usr, token=token))
    html_msg = render_template('email/reset_password.html', user=usr, token=token)
    msg.add_alternative(html_msg, subtype="html")

    send_email(smtpserver, msg)


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    frmss = StartStop()
    return render_template('index.html', title='Inicio', serv=True, form=frmss)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    frm_lgin = LoginForm()
    if frm_lgin.validate_on_submit():
        user = User.query.filter_by(username=frm_lgin.username.data).first()
        if user is None or not user.check_password(frm_lgin.password.data):
            flash('Nombre de usuario o password invalido')
            return redirect(url_for('login'))
        login_user(user, remember=frm_lgin.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Ingreso', form=frm_lgin)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        wappdb.session.add(user)
        wappdb.session.commit()
        flash('Se ha registrado el usuario nuevo.')
        return redirect(url_for('index'))
    return render_template('register.html', title='Register', form=form)


@app.route('/usuarios')
@login_required
def usuarios():
    u = User.query.all()
    return render_template('usuarios.html', title='Usuarios', users=u)


@app.route('/perfil/<username>', methods=['GET', 'POST'])
@login_required
def perfil(username):
    usr = User.query.filter_by(username=username).first_or_404()
    frm = EditProfileForm(usr.username, usr.email)
    frm.username.id = usr.username
    frm.email.id = usr.email
    if frm.validate_on_submit():
        user = User.query.filter_by(username=frm.original_username).first()
        user.username = frm.username.data
        user.email = frm.email.data
        if frm.oldpassword != "":
            user.set_password(frm.newpassword.data)
        wappdb.session.commit()
        flash('Actualización completada con éxito.')
        return redirect(url_for('usuarios'))
    return render_template('perfil.html', user=usr, form=frm)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Restablecer Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        wappdb.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)