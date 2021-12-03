import json
import os
from functools import wraps

from flask import jsonify, make_response, abort
from flask import request
from flask_limiter import Limiter

from app import app


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
            abort_json(422, "OpenAlex API key required")
        return route(*args, **kwargs)
    return _api_key_required


def request_api_key():
    return request.args.get('api_key') or request.headers.get('OpenAlex-API-Key')


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
        'api_key': request_api_key()
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
