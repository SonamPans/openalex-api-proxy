import datetime
import json
import os
from functools import wraps

import shortuuid
from flask import abort, g, jsonify, make_response
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
        request_key = request.args.get('api_key') or request.headers.get('OpenAlex-API-Key')

        if not request_key:
            abort_json(422, 'OpenAlex API key required. Please register a key at https://openalex.org/rest-api/register')

        api_key = APIKey.query.filter(APIKey.key == request_key).scalar()

        if not api_key:
            abort_json(422, f'Unrecognized API key {request_key}. Please register a key at https://openalex.org/rest-api/register')
        elif not api_key.active:
            abort_json(422, f'OpenAlex API key {api_key.key} has been deactivated.')
        elif api_key.expires and api_key.expires < datetime.datetime.utcnow():
            abort_json(422, f'OpenAlex API key {api_key.key} expired {api_key.expires.isoformat()}.')

        g.api_key = api_key
        return route(*args, **kwargs)
    return _api_key_required


def proxy_rate_limit():
    api_key = g.get('api_key')
    if api_key and api_key.is_demo:
        #  100 per day per remote address
        return '100/day'
    else:
        # 100,000 per day per key
        return '100000/day'


def proxy_rate_key():
    api_key = g.get('api_key')
    if api_key and api_key.is_demo:
        #  100 per day per remote address
        return get_remote_address()
    else:
        # 100,000 per day per key
        return f'{g.api_key.key}'


def api_rate_limit_key():
    return f'{g.api_key.key}'


limiter = Limiter(app, key_func=get_remote_address)


@app.route('/<path:request_path>', methods=['GET', 'POST'])
@api_key_required
@limiter.limit(limit_value=proxy_rate_limit, key_func=proxy_rate_key)
def forward_request(request_path):
    return jsonify({
        'method': request.method,
        'path': request_path,
        'args': request.args,
        'data': str(request.get_data()),
        'headers': dict(request.headers),
        'api_key': g.api_key.to_dict()
    })


@app.route('/key/register', methods=['POST'])
@limiter.limit('1/second', key_func=get_remote_address)
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
        incident_id = shortuuid.uuid()
        logger.exception(f'error {incident_id} saving API key: {api_key.to_dict()}\n{e}')
        abort_json(500, {'incident_id': incident_id, 'message': 'Error generating API key.'})

    return jsonify(api_key.to_dict())


def duplicate_email_message(api_key):
    return f"Sorry, an API key has already been registered for {api_key.email}. \
Please check your inbox for a key sent on {api_key.created.date()}. \
If you believe this is a mistake, let us know at team@ourresearch.org."


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
