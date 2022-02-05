import flask
from flask import Blueprint, jsonify


blueprint = Blueprint('api', __name__, url_prefix='/api')


@blueprint.route('/hello_world')
def api_hello_world():
    print(flask.current_app.config.db)
    print("send-in greets")
    return jsonify({'message': 'Hello World!', "success": True})
