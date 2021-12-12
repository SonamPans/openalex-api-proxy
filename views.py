import datetime
import hashlib
import json
import os
from functools import wraps
import re

import requests
import shortuuid
from flask import abort, g, jsonify, make_response
from flask import request
from flask_limiter import Limiter
from werkzeug.exceptions import BadRequest
from werkzeug.http import http_date

from api_key import APIKey
from app import app, db
from app import entity_api, slice_and_dice_api
from app import logger
from app import memcached
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

        # TEMPORARY FOR DEVELOPMENT
        # all requests are using the demo key, and users don't actually have to use an api key at all.
        request_key = "gWt4qXZuXTqUAuvZMJjwRe"

        if not request_key:
            abort_json(422, 'OpenAlex API key required. Please register a key at https://openalex.org/rest-api')

        api_key = APIKey.query.filter(APIKey.key == request_key).scalar()

        if not api_key:
            abort_json(422, f'Unrecognized API key {request_key}. Please register a key at https://openalex.org/rest-api')
        elif not api_key.active:
            abort_json(422, f'OpenAlex API key {api_key.key} has been deactivated.')
        elif api_key.expires and api_key.expires < datetime.datetime.utcnow():
            abort_json(422, f'OpenAlex API key {api_key.key} expired {api_key.expires.isoformat()}.')

        g.api_key = api_key




        return route(*args, **kwargs)
    return _api_key_required


def proxy_rate_limit():
    if (api_key := g.get('api_key')) and api_key.is_demo:
        #  1000 per day per remote address
        return '1000/day'
    else:
        # 100,000 per day per key
        return '100000/day'


def proxy_rate_key():
    api_key = g.get('api_key')
    if api_key and api_key.is_demo:
        #  100 per day per remote address
        return remote_address()
    else:
        # 100,000 per day per key
        return f'{g.api_key.key}'


def api_rate_limit_key():
    return f'{g.api_key.key}'


def remote_address():
    if forwarded_for := request.headers.getlist('X-Forwarded-For'):
        return forwarded_for[0]
    else:
        return request.remote_addr


@app.errorhandler(429)
def rate_limit_handler(e):
    if (api_key := g.get('api_key')) and api_key.is_demo:
        msg = f'This is a demo API key for use in documentation, please register your own at https://openalex.org/rest-api'
    else:
        msg = f'Too many requests, exceeded {e.description}'

    return make_response(jsonify({'error': msg}), 429)


@app.after_request
def after_request(response):
    if response.status_code != 429 and 'Retry-After' in response.headers:
        del response.headers['Retry-After']

    if rate_limit_reset := response.headers.get('X-RateLimit-Reset'):
        try:
            response.headers['X-RateLimit-Reset'] = http_date(int(rate_limit_reset))
        except ValueError:
            pass

    return response


limiter = Limiter(app, key_func=remote_address)


def select_worker_host(request_path):
    print("request_path", request_path)

    # if it's a path, it goes to the entity api
    if '/' in request_path[:-1]:
        return entity_api

    # if it's like W123 it's an OpenAlex ID and goes to the entity API
    elif len(re.findall("^[wWiIvVaAcC]/d+$", request_path)):
        return entity_api

    # slice, dice. goes to elasticsearch
    else:
        return slice_and_dice_api


@app.route('/<path:request_path>', methods=['GET'])
@api_key_required
@limiter.limit(limit_value=proxy_rate_limit, key_func=proxy_rate_key)
def forward_request(request_path):
    worker_host = select_worker_host(request_path)
    worker_url = f'{worker_host}/{request_path}'
    worker_params = dict(request.args)
    if 'api_key' in worker_params:
        del worker_params['api_key']

    cache_key = hashlib.sha256(
        json.dumps({'url': worker_url, 'args': worker_params}, sort_keys=True).encode('utf-8')
    ).hexdigest()

    response_source = 'cache'

    # if not (response_attrs := memcached.get(cache_key)):

    # disable caching
    if True:
        try:
            worker_response = requests.get(worker_url, params=worker_params)
            response_source = worker_response.url

            response_attrs = {
                'status_code': worker_response.status_code,
                'content': worker_response.content,
                'headers': dict(worker_response.headers),
            }

            if worker_response.status_code < 500:
                memcached.set(cache_key, response_attrs)

        except requests.exceptions.RequestException:
            response_attrs = {
                'status_code': 500,
                'content': 'There was an error processing your request. Please try again.',
                'headers': {}
            }

    logger.info(json.dumps(
        {
            'grep_sentinel': 'dw9vwocmxd',
            'api_key': g.api_key.key,
            'path': request_path,
            'args': dict(request.args),
            'response_source': response_source,
            'cache_key': cache_key,
            'response_status_code': response_attrs['status_code'],
        }
    ))

    response = make_response(response_attrs['content'], response_attrs['status_code'])

    for k, v in response_attrs['headers'].items():
        if k == 'Content-Type' or k.startswith('Access-Control-'):
            response.headers[k] = v

    return response


@app.route('/key/register', methods=['POST'])
@limiter.limit('1/second', key_func=remote_address)
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


@app.route('/', methods=["GET", "POST"])
def base_endpoint():
    return jsonify({
        "version": "0.0.1",
        "documentation_url": "https://openalex.org/rest-api",
        "msg": "Don't panic"
    })


def duplicate_email_message(api_key):
    return f"Sorry, an API key has already been registered for {api_key.email}. \
Please check your inbox for a key sent on {api_key.created.date()}. \
If you believe this is a mistake, let us know at team@ourresearch.org."


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
