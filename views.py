import json
import os
from functools import wraps

import shortuuid
from flask import jsonify, make_response, abort
from flask import request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import BadRequest

from api_key import APIKey
from app import app, db
from app import logger
from emailer import create_email, send


def abort_json(status_code, msg):
    body_dict = {
        "HTTP_status_code": status_code,
        "message": msg,
        "error": True
    }
    resp_string = json.dumps(body_dict, sort_keys=True, indent=4)
    resp = make_response(resp_string, status_code)
    resp.mimetype = "application/json"
    abort(resp)


def api_key_required(route):
    @wraps(route)
    def _api_key_required(*args, **kwargs):
        if not request_api_key():
            abort_json(422, 'OpenAlex API key required. Please register a key at https://openalex.org/rest-api/register')
        return route(*args, **kwargs)
    return _api_key_required


def request_api_key():
    request_key = request.args.get('api_key') or request.headers.get('OpenAlex-API-Key')

    if request_key:
        return APIKey.query.filter(APIKey.key == request_key, APIKey.active == True).scalar()
    else:
        return None


limiter = Limiter(app, key_func=request_api_key)


@app.route('/<path:request_path>', methods=['GET', 'POST'])
@api_key_required
@limiter.limit('100000/day;20/second')
def forward_request(request_path):
    return jsonify({
        'method': request.method,
        'path': request_path,
        'args': request.args,
        'data': str(request.get_data()),
        'headers': dict(request.headers),
        'api_key': request_api_key().to_dict()
    })


@app.route('/key/register', methods=['POST'])
@limiter.limit('1/second', key_func=get_remote_address, )
def register_key():
    request_email = None

    try:
        request_email = request.json['email']
    except (KeyError, TypeError, BadRequest):
        pass

    if not request_email:
        abort_json(400, 'POST a JSON object with the email address to register, like {"email": "user@example.com"}')

    if existing_key := APIKey.query.filter(APIKey.email == request_email).scalar():
        abort_json(400, duplicate_email_message(existing_key))

    api_key = APIKey(email=request_email)
    try:
        db.session.add(api_key)
        db.session.commit()
        welcome_email = create_email(
            request_email,
            'Your OpenAlex REST API key',
            'api_key_registration',
            {
                'email': request_email,
                'key': api_key.key
            }
        )
        send(welcome_email, for_real=True)
    except Exception as e:
        incident_key = shortuuid.uuid()
        logger.exception(f'error {incident_key} saving API key: {api_key.to_dict()}\n{e}')

        if f'Key (email)=({api_key.email}) already exists' in str(e):
            abort_json(400, duplicate_email_message(api_key))

        abort_json(500, {'error_code': incident_key, 'exception': str(e)})

    return jsonify(api_key.to_dict())


def duplicate_email_message(api_key):
    return f"Sorry, an API key has already been registered for {api_key.email}. \
Please check your inbox for a key sent on {api_key.created.date()}. \
If you believe this is a mistake, let us know at team@ourresearch.org and we'll sort it out!"


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
