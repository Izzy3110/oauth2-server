import os
from flask import Flask
# from .blueprints.basic_endpoints.api import blueprint as api_endpoints
from .models import db
from .oauth2 import config_oauth, require_oauth
from .routes import bp


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_object('website.settings')
    # from .blueprints.basic_endpoints import blueprint as basic_endpoints
    # from .blueprints.jinja_endpoint import blueprint as jinja_template_blueprint
    # app.register_blueprint(basic_endpoints)
    # app.register_blueprint(jinja_template_blueprint)
    # app.register_blueprint(api_endpoints)

    # Fails
    # # from .blueprints.documented_endpoints import blueprint as documented_endpoint
    # app.register_blueprint(documented_endpoint)

    # load environment configuration
    if 'WEBSITE_CONF' in os.environ:
        app.config.from_envvar('WEBSITE_CONF')

    # load app specified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)

    setup_app(app)
    return app


def setup_app(app):
    # Create tables if they do not exist already
    @app.before_first_request
    def create_tables():
        db.create_all()

    os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

    db.init_app(app)

    config_oauth(app)

    app.register_blueprint(bp, url_prefix='')
