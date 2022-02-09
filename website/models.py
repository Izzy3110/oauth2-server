import time
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)

from .wyl.security import SecurityManager


db = SQLAlchemy()


class SpotifyLastSongs(db.Model):
    __tablename__ = 'spotify_last_songs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')
    artist = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), nullable=False)
    song_id = db.Column(db.String(250), nullable=False)
    

class Scopes(db.Model):
    __tablename__ = 'scopes'
    id = db.Column(db.Integer, primary_key=True)
    base = db.Column(db.String(250))
    section = db.Column(db.String(250))
    scope = db.Column(db.String(250), nullable=False)
    url = db.Column(db.String(250), nullable=False)
    methods = db.Column(db.String(250), nullable=False)
    date_first_seen = db.Column(db.String(120))
    
class Applications(db.Model):
    __tablename__ = 'applications'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(250), unique=True, nullable=False)
    name = db.Column(db.String(250), unique=True, nullable=False)
    user_id = db.Column(db.String(250), unique=True, nullable=False)
    date_registered = db.Column(db.String(120))
    date_modified = db.Column(db.String(120))
    client_ids = db.Column(db.String(250))

class ApplicationsModifications(db.Model):
    __tablename__ = 'applications_modifications'
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(
    db.Integer, db.ForeignKey('applications.id', ondelete='CASCADE'))
    mod_name = db.Column(db.String(120))
    modification_made = db.Column(db.String(120))
    date_modified = db.Column(db.String(120))
    applications = db.relationship('Applications')
        

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=False)
    date_registered = db.Column(db.String(120))
    date_last_login = db.Column(db.String(120))
    date_last_logout = db.Column(db.String(120))
    authenticated = db.Column(db.Integer)

    def __str__(self):
        return self.username

    def get_user_id(self):
        return self.id

    @staticmethod
    def get_iv_data(bytes_):
        bio = BytesIO(bytes_)
        iv = bio.read(16)
        data = bio.read()
        bio.close()
        return iv, data

    def check_password(self, password):

        sec_man = SecurityManager()
        sec_man.setup_key()
        decrypted_pass = sec_man.decrypt_password(self.password)
        print("provided pass: " + password)
        print("dec: "+decrypted_pass)
        return password == decrypted_pass


class UserDetails(db.Model):
    __tablename__ = 'user_details'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    first_name = db.Column(db.String(120))
    last_name = db.Column(db.String(120))
    local_street = db.Column(db.String(120))
    local_street_no = db.Column(db.String(120))
    local_plz = db.Column(db.String(120))
    local_city = db.Column(db.String(120))
    local_phone = db.Column(db.String(120))

    user = db.relationship('User')


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()
