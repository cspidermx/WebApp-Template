from webapp import wappdb
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from webapp import login
from time import time
import jwt
from webapp import app


class User(UserMixin, wappdb.Model):
    id = wappdb.Column(wappdb.Integer, primary_key=True)
    username = wappdb.Column(wappdb.String(64), index=True, unique=True)
    email = wappdb.Column(wappdb.String(120), index=True, unique=True)
    password_hash = wappdb.Column(wappdb.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Usuario {}>'.format(self.username)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'restablecer_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            idtkn = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['restablecer_password']
        except jwt.ExpiredSignatureError:
            return 'Firma ha expirado. Intente firmarse de nuevo.'
        except jwt.InvalidTokenError:
            return 'Token invalido. Intente firmarse de nuevo.'
        return User.query.get(idtkn)


@login.user_loader
def load_user(idusr):
    return User.query.get(int(idusr))
