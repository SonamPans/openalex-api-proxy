import os

from flask import jsonify
from flask import request

from app import app


@app.route("/<path:request_path>", methods=["GET"])
def handle_request(request_path):
    return jsonify({
        'method': request.method,
        'path': request_path,
        'args': request.args,
        'headers': dict(request.headers),
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)