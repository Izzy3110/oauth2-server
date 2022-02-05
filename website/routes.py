import os.path
import shutil
import time
import flask
import sqlalchemy.exc
import uuid
from flask import Blueprint, request, session, url_for, current_app
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import db, User, OAuth2Client, Applications
from .oauth2 import authorization, require_oauth
from datetime import datetime

from .wyl.security import SecurityManager
from .wyl.mail_listener import Mail
from .wyl.weather import Weather

bp = Blueprint('home', __name__, template_folder="website/templates", static_folder="website/static",
               static_url_path="/static")


def generate_new_key(current_sec_man):
    sec_man_tmp = SecurityManager()
    sec_man_tmp.setup_key(key_file="key.bin.tmp")

    for single_user in User.query.all():
        decrypted_pass = current_sec_man.decrypt_password(single_user.password)
        new_password = sec_man_tmp.encrypt_password(decrypted_pass)
        current_user_ = User.query.filter_by(username=single_user.username).first()
        if current_user_ is not None:
            print("processing: " + current_user_.email)
            current_user_.password = new_password
            db.session.commit()

    shutil.copy2(sec_man_tmp.key_file, current_sec_man.key_file)
    os.remove(sec_man_tmp.key_file)


def gen_date():
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


def current_user(session_):
    if 'id' in session_:
        uid = session_['id']
        return User.query.get(uid)
    return None


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


authenticated = {}
is_login = False

method_names = ["POST","GET"]


scope_files = ["website/routes.py"]

def get_scopes():
    scope_urls = []
    for scope_file in scope_files:
        lines = open(scope_file).read().splitlines()
        lines_bp = []
        for line_i in range(0, len(lines)):
            line = lines[line_i]
            if line.startswith("@bp"):
                
                if "@require_oauth" in lines[line_i+1]:
                    lines_a_ = []
                    for line_ in line.lstrip("@bp.route('").split("/"):
                        if len(line_) > 0:
                            if "'" in line_:
                                lines_a_.append(line_.split("'")[0])
                            else:
                                lines_a_.append(line_)
                    scope_method = "GET"
                    spl_ = line.replace('"',"'").split("'")
                    for item_i_ in range(0, len(spl_)):
                        item_ = spl_[item_i_]
                        if "methods" in item_:
                            if spl_[item_i_+1] in method_names:
                                scope_method = spl_[item_i_+1]
                    scope_name = lines[line_i+1].replace('"',"'").split("'")[1]
                    base_ = None
                    section_ = None
                    if ":" in scope_name:
                        splitted_ = scope_name.split(":")
                        base_ = splitted_[0]
                        section_ = splitted_[1]
                    new_scope = {
                    "base": base_,
                    "section": section_,
                    "url": "/"+"/".join(lines_a_),
                    "scope": scope_name,
                    "method": scope_method
                    }
                    lines_bp.append(new_scope)
                else:
                    if "def" in lines[line_i+1]:
                        method_ = "GET"
                        # print(line)
                        if "methods" in line:
                            tmp_ = line.split("'")
                            for t_i in range(0, len(tmp_)):
                                t_ = tmp_[t_i]
                                if "methods" in t_:
                                    method_ = tmp_[t_i+1]
                        
                        scope_urls.append({"url": line.split("'")[1], "method": method_})
                        # print(lines[line_i+1])
    return {"scopes": lines_bp, "urls": scope_urls}


class ValidateFormInput(object):
    username = None
    password = None
    email = None
    variables = {
        "username": None,
        "password": None,
        "email": None,
    }
    variable_min_length = {
        "username": 4,
        "password": 8,
        "email": 6,
    }
    errors = []
    tests_ok = None
    tests_failed = None

    def __init__(self, username=None, password=None, email=None):
        if username is not None:
            self.username = username
            self.variables["username"] = self.username

        if password is not None:
            self.password = password
            self.variables["password"] = self.password

        if email is not None:
            self.email = email
            self.variables["email"] = self.email

    def test_length(self, min_length=None):
        self.errors = []
        tests_ok = []
        tests_failed = []
        for variable_name in self.variables.keys():
            if self.variables[variable_name] is not None:
                # print(variable_name)
                # print(self.variables[variable_name])
                
                min_ = self.variable_min_length[variable_name] if min_length is None else min_length
                # print("len("+self.variables[variable_name]+") >= "+str(min_))
                # print(len(self.variables[variable_name]) >= min_)
                ret = True if len(self.variables[variable_name]) >= min_ else False
                ret_data = "> "+str(min_)
                if ret:
                    tests_ok.append({"var": variable_name, "test": "len", "ret": ret_data})
                else:
                    tests_failed.append({"var": variable_name, "test": "len", "ret": ret_data})
                    if len(self.variables[variable_name]) == 0:
                        self.errors.append({
                            "type": variable_name,
                            "error_code": "EMPTY_STRING",
                            "min_length": ret_data
                        })
                    else:
                        self.errors.append({
                            "type": variable_name,
                            "error_code": "STRING_LENGTH",
                            "min_length": ret_data
                        })
                
        self.tests_ok = tests_ok
        self.tests_failed = tests_failed
        return self

errors_ = None

@bp.route('/', methods=['GET', 'POST'])
def home():
    global authenticated, is_login, errors_
    print(session.keys())
    sec_man = SecurityManager()
    sec_man.setup_key()
    # print(len(current_app.config["SECRET_KEY"]))
    clients = []
    password_ = None
    if request.method == "POST":
        # print("is post")
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if len(password) > 0:
            password_ = sec_man.encrypt_password(password)
            if not email:
                # print("is login")
                is_login = True

        user = User.query.filter_by(username=username).first()

        if not user:
            errors_ = []
            errors_ =  ValidateFormInput(username, password, email).test_length().errors
            if len(errors_) > 0:
                # print(len(errors_))
                return render_template('clients.html', user=None, clients=[], errors=errors_)

            now_ = gen_date()
            user = User(username=username, password=password_ if password_ is not None else password, email=email,
                        date_registered=now_, date_last_login=now_)

            db.session.add(user)

            session['id'] = user.id

            try:
                db.session.commit()
            except sqlalchemy.exc.IntegrityError as e:
                if "UNIQUE" in str(e):
                    error = {
                        "type": "email",
                        "error_code": "NOT_UNIQUE_STRING"
                    }
                    errors_.append(error)
                    return render_template('clients.html', user=None, clients=[], errors=errors_)

        else:
            if is_login:
                if not user.check_password(password):
                    errors_ = []
                    error = {
                        "type": "password",
                        "error_code": "NOT_MATCH"
                    }
                    errors_.append(error)
                    return render_template('clients.html', user=None, clients=[], errors=errors_)

            time_then = time.mktime(datetime.strptime(user.date_last_login, '%Y-%m-%d %H:%M:%S.%f').timetuple())

            elapsed_ = int(time.time() - time_then)

            if elapsed_ >= 1:
                dt_object = datetime.fromtimestamp(time.time())
                user.date_last_login = dt_object.strftime('%Y-%m-%d %H:%M:%S.%f')

            user.authenticated = 1

            db.session.commit()

            session['id'] = user.id
            session['user'] = str(user)
            session['authenticated'] = True
            clients = OAuth2Client.query.filter_by(user_id=user.id).all()

    else:
        print(session)
        user = current_user(session)
        
            
    if user is not None:

        clients = OAuth2Client.query.filter_by(user_id=user.id).all()

        return render_template('clients.html', user=user, user_date_last_login=user.date_last_login, clients=clients,
                               errors={}, authenticated=authenticated)

    else:

        return render_template('clients.html', user=None, user_date_last_login="", clients=clients,
                               errors={}, authenticated=authenticated)

@bp.route('/scopes', methods=['GET', 'POST'])
def scopes_template_index():
    user = None
    scopes_ = get_scopes()
    if "authenticated" in session.keys():
        if session["id"] is not None:
            now_ = gen_date()
            user = User.query.filter_by(username=session["user"] ).first()
            clients = OAuth2Client.query.filter_by(user_id=user.id).all()
            return render_template('scopes.html', user=user, user_date_last_login=user.date_last_login, clients=clients,
                               errors={}, scopes=scopes_)
    if request.method == "POST":
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if len(password) > 0:
            sec_man = SecurityManager()
            sec_man.setup_key()
            password_ = sec_man.encrypt_password(password)
            print("pass: "+password_)
            user = User.query.filter_by(username=username).first()
            if not user.check_password(password):
                    errors_ = []
                    error = {
                        "type": "password",
                        "error_code": "NOT_MATCH"
                    }
                    errors_.append(error)
                    return render_template('clients.html', user=None, clients=[], errors=errors_)
            time_then = time.mktime(datetime.strptime(user.date_last_login, '%Y-%m-%d %H:%M:%S.%f').timetuple())

            elapsed_ = int(time.time() - time_then)

            if elapsed_ >= 1:
                dt_object = datetime.fromtimestamp(time.time())
                user.date_last_login = dt_object.strftime('%Y-%m-%d %H:%M:%S.%f')

            user.authenticated = 1

            db.session.commit()

            session['id'] = user.id
            session['user'] = str(user)
            session['authenticated'] = True
            clients = OAuth2Client.query.filter_by(user_id=user.id).all()
            return render_template('scopes.html', user=user, user_date_last_login=user.date_last_login, clients=clients if clients is not None else [],
                               errors=[], scopes=scopes_)
    return render_template('scopes.html', user=None, scopes=scopes_)


@bp.route('/api/scopes', methods=['POST'])
@require_oauth("scopes:write")
def api_scopes_write():
    return jsonify({"set_scopes": False, "aler": "WARNING"})

@bp.route('/api/scopes', methods=['GET'])
@require_oauth("scopes:read")
def scopes_index():
    scopes_ = get_scopes()
    return jsonify({"scopes": scopes_})

@bp.route('/create_application', methods=['POST', 'GET'])
def create_application():
    if request.method == "POST":
        application_name = request.form.get("application_name")
        if len(application_name) > 0:
            application_uuid = str(uuid.uuid4())
            print("new application_name: "+application_uuid)
            
        if "authenticated" in session.keys():
            if session["id"] is not None:
                    now_ = gen_date()
                    user = User.query.filter_by(username=session["user"] ).first()
                    
                    now_ = gen_date()
                    application_ = Applications(uuid=application_uuid, name=application_name, date_registered=now_, date_modified=now_, user_id=session["id"])
                    db.session.add(application_)
                    db.session.commit()
                    
                    clients = OAuth2Client.query.filter_by(user_id=user.id).all()
                    return render_template('create_application.html', user=user, user_date_last_login=user.date_last_login, clients=clients,
                                       errors=[])#
    else:
        if "authenticated" in session.keys():
            
            if session["id"] is not None:
                    now_ = gen_date()
                    user = User.query.filter_by(username=session["user"] ).first()
                    clients = OAuth2Client.query.filter_by(user_id=user.id).all()
                    return render_template('create_application.html', user=user, user_date_last_login=user.date_last_login, clients=clients,
                                       errors=[])
    return render_template("create_application.html")


@bp.route('/applications', methods=['GET', 'POST'])
def applications_index():
    dbApplications = Applications().query.all()
    if "authenticated" in session.keys():
        print("is authenticated")
        print(session)
        user = User.query.filter_by(username=session["user"] ).first()
        session["id"] = user.id
        if session["id"] is not None:
                now_ = gen_date()
                user = User.query.filter_by(username=session["user"] ).first()
                clients = OAuth2Client.query.filter_by(user_id=user.id).all()
                return render_template('applications.html', user=user, user_date_last_login=user.date_last_login, clients=clients,
                                   errors=[])
    # print(dbApplications)
    # return render_template('child.html', user=None, scopes=scopes_)
    return render_template('applications.html')
    
    
@bp.route('/logout', methods=['GET', 'POST'])
def logout():
    user = User.query.filter_by(username=session["user"]).first()
    if user:
        user.authenticated = 0
        user.date_last_logout = gen_date()
        db.session.commit()

    if session["user"] in authenticated.keys():
        if authenticated[session["user"]]:
            authenticated[session["user"]] = 0

    del session['id']
    del session['authenticated']
    return redirect('/')


@bp.route('/create_client', methods=('GET', 'POST'))
def create_client():
    user = current_user(session)

    if not user:
        return redirect('/')

    if request.method == 'GET':
        return render_template('create_client.html')

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )

    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }

    client.set_client_metadata(client_metadata)

    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    db.session.add(client)
    db.session.commit()

    return redirect('/')


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user(session)

    if not user:
        return redirect(url_for('home.home', next=request.url))

    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return error.error
        print(grant)
        return render_template('authorize.html', user=user, grant=grant)

    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()

    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None

    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')


last_weather_t = 0
last_weather_data_ = {}


@bp.route('/api/weather/<lat>,<lon>', methods=['GET'])
@require_oauth('api:weather')
def api_weather(lat, lon):
    global last_weather_t, last_weather_data_

    flask.current_app.require_oauth = require_oauth
    if last_weather_t == 0:
        last_weather_t = time.time()
        last_weather_data_ = {
            "t": time.time(),
            "data": Weather("b32454941f463f3cc6056da4bcf47fc9", float(lat), float(lon)).last_weather_data
        }
    else:
        if int(time.time() - last_weather_t) > 30:
            last_weather_t = time.time()
            last_weather_data_ = {
                "t": time.time(),
                "data": Weather("b32454941f463f3cc6056da4bcf47fc9", float(lat), float(lon)).last_weather_data
            }

    return jsonify(success=False, last_data=last_weather_data_)


@bp.route('/api/mailscmd/<email>', methods=['GET'])
@require_oauth('api:mails')
def api_mailscmd(email):
    print(email)
    m = Mail()
    message_ids = list(m.filter_results.keys())

    return jsonify(email=email, unseen_messages=len(message_ids), filter=m.filter_)


@bp.route('/api/projects', methods=["GET"])
@require_oauth('projects:read')
def api_projects():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)


@bp.route('/api/projects', methods=["POST"])
@require_oauth('projects:write')
def api_projects_write():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)

@bp.route('/api/me')
@require_oauth('profile:read')
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)


@bp.route('/api/me', methods=['POST'])
@require_oauth('profile:write')
def api_me_write():
    user = current_token.user
    sec_man = SecurityManager()
    sec_man.setup_key()

    new_password = request.form.get('password')
    new_email = request.form.get('email')

    if new_password is not None:
        print("new: " + sec_man.encrypt_password(new_password))
        user_new = User.query.filter_by(username=user.username).first()
        if user_new is not None:
            key = None
            if os.path.isfile("key.bin"):
                with open("key.bin", "rb") as key_f:
                    key = key_f.read()
            if key is not None:
                if len(new_password) > 0:
                    password_ = sec_man.encrypt_password(new_password)

                    # write to db
                    user_new.password = password_
                    db.session.commit()

                    return jsonify(id=user.id, username=user.username, action="change_password", success=True,
                                   message="updated password")
            return jsonify(id=user.id, username=user.username, email=new_password, message="updating password")

    if new_email is not None:
        user_ = User.query.filter_by(email=new_email).first()
        if user_ is None:
            user_new = User.query.filter_by(username=user.username).first()
            if user_new is not None:

                # write to db
                user_new.email = new_email
                db.session.commit()

            else:
                return jsonify(id=user.id, username=user.username, email=new_email,
                               error="no user: " + user.username)

            return jsonify(id=user.id, username=user.username, email=new_email, message="updated email")

        else:
            return jsonify(id=user.id, username=user.username, email=new_email,
                           error="email already set to " + new_email)

    return jsonify(id=user.id, username=user.username)
