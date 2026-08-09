import jsonschema
import jwt

from config import db, vuln_app
from api_views.json_schemas import *
from flask import jsonify, Response, request, json
from models.user_model import User

AUTHENTICATION_FAILURE_MESSAGE = "Username or Password Incorrect!"
REGISTRATION_RESPONSE_MESSAGE = "Successfully registered. Login to receive an auth token."
EMAIL_LOCAL_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.!#$%&'*+/=?^_`{|}~-")
EMAIL_DOMAIN_CHARACTERS = frozenset(
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-')


def is_valid_email(email):
    # ASVS 1.2.9: bounded, non-regex parsing avoids attacker-controlled backtracking.
    if not isinstance(email, str) or len(email) > 254 or email.count('@') != 1:
        return False
    local_part, domain = email.rsplit('@', 1)
    if not local_part or len(local_part) > 64:
        return False
    if any(character not in EMAIL_LOCAL_CHARACTERS for character in local_part):
        return False
    labels = domain.split('.')
    if len(labels) < 2 or len(labels[-1]) < 2:
        return False
    return all(
        0 < len(label) <= 63
        and label[0] != '-'
        and label[-1] != '-'
        and all(character in EMAIL_DOMAIN_CHARACTERS for character in label)
        for label in labels
    )


def error_message_helper(msg):
    if isinstance(msg, dict):
        return '{ "status": "fail", "message": "' + msg['error'] + '"}'
    else:
        return '{ "status": "fail", "message": "' + msg + '"}'


def get_all_users():
    return_value = jsonify({'users': User.get_all_users()})
    return return_value


def me():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        responseObject = {
            'status': 'success',
            'data': {
                'username': user.username,
                'email': user.email,
                'admin': user.admin
            }
        }
        return Response(json.dumps(responseObject), 200, mimetype="application/json")
        

def get_by_username(username):
    if User.get_user(username):
        return Response(str(User.get_user(username)), 200, mimetype="application/json")
    else:
        return Response(error_message_helper("User not found"), 404, mimetype="application/json")


def register_user():
    request_data = request.get_json()
    # check if user already exists
    user = User.query.filter_by(username=request_data.get('username')).first()
    if not user:
        try:
            # validate the data are in the correct form
            jsonschema.validate(request_data, register_user_schema)
            # ASVS 8.2.3: privilege fields are server-owned and never accepted here.
            user = User(username=request_data['username'], password=request_data['password'],
                        email=request_data['email'])
            db.session.add(user)
            db.session.commit()

            responseObject = {
                'status': 'success',
                'message': REGISTRATION_RESPONSE_MESSAGE
            }

            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        except jsonschema.exceptions.ValidationError as exc:
            return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    else:
        # ASVS 6.3.8: duplicate registration must not reveal valid usernames.
        responseObject = {
            'status': 'success',
            'message': REGISTRATION_RESPONSE_MESSAGE
        }
        return Response(json.dumps(responseObject), 200, mimetype="application/json")


def login_user():
    request_data = request.get_json()

    try:
        # validate the data are in the correct form
        jsonschema.validate(request_data, login_user_schema)
        # fetching user data if the user exists
        user = User.query.filter_by(username=request_data.get('username')).first()
        if user and request_data.get('password') == user.password:
            auth_token = user.encode_auth_token(user.username)
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'auth_token': auth_token
            }
            return Response(json.dumps(responseObject), 200, mimetype="application/json")
        # ASVS 6.3.8: use one response for unknown users and invalid passwords.
        return Response(error_message_helper(AUTHENTICATION_FAILURE_MESSAGE), 200,
                        mimetype="application/json")
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")
    except:
        return Response(error_message_helper("An error occurred!"), 200, mimetype="application/json")


def token_validator(auth_header):
    if auth_header:
        try:
            auth_token = auth_header.split(" ")[1]
        except:
            auth_token = ""
    else:
        auth_token = ""
    if auth_token:
        # if auth_token is valid we get back the username of the user
        return User.decode_auth_token(auth_token)
    else:
        return {'error': 'Invalid token. Please log in again.'}


def update_email(username):
    request_data = request.get_json()
    try:
        jsonschema.validate(request_data, update_email_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        email = request_data.get('email')
        if not is_valid_email(email):
            return Response(error_message_helper("Please Provide a valid email address."), 400,
                            mimetype="application/json")
        user = User.query.filter_by(username=resp['sub']).first()
        user.email = email
        db.session.commit()
        responseObject = {
            'status': 'success',
            'data': {
                'username': user.username,
                'email': user.email
            }
        }
        return Response(json.dumps(responseObject), 204, mimetype="application/json")


def update_password(username):
    request_data = request.get_json()
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        # ASVS 8.2.2: the authenticated identity owns this credential.
        if username != resp['sub']:
            return Response(error_message_helper("Forbidden"), 403, mimetype="application/json")
        if request_data.get('password'):
            user = User.query.filter_by(username=resp['sub']).first()
            if not user:
                return Response(error_message_helper("User Not Found"), 404, mimetype="application/json")
            user.password = request_data.get('password')
            db.session.commit()
            responseObject = {
                'status': 'success',
                'Password': 'Updated.'
            }
            return Response(json.dumps(responseObject), 204, mimetype="application/json")
        else:
            return Response(error_message_helper("Malformed Data"), 400, mimetype="application/json")


def delete_user(username):
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    else:
        user = User.query.filter_by(username=resp['sub']).first()
        if user.admin:
            if bool(User.delete_user(username)):
                responseObject = {
                    'status': 'success',
                    'message': 'User deleted.'
                }
                return Response(json.dumps(responseObject), 200, mimetype="application/json")
            else:
                return Response(error_message_helper("User not found!"), 404, mimetype="application/json")
        else:
            return Response(error_message_helper("Only Admins may delete users!"), 401, mimetype="application/json")
