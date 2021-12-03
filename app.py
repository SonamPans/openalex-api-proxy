import logging
import os
import sys
import warnings
from urllib.parse import urlparse

import limits.errors
import limits.util
import redis
from flask import Flask
from flask_compress import Compress
from limits.storage.redis import RedisStorage

app = Flask(__name__)
app.config['RATELIMIT_HEADERS_ENABLED'] = os.getenv('RATELIMIT_HEADERS_ENABLED')

redis_url = os.getenv('REDIS_URL')
app.config['RATELIMIT_STORAGE_URL'] = redis_url


def redis_init(self, uri: str, **options):
    """
    :param uri: uri of the form `redis://[:password]@host:port`,
     `redis://[:password]@host:port/db`,
     `rediss://[:password]@host:port`, `redis+unix:///path/to/sock` etc.
     This uri is passed directly to :func:`redis.from_url` except for the
     case of `redis+unix` where it is replaced with `unix`.
    :param options: all remaining keyword arguments are passed
     directly to the constructor of :class:`redis.Redis`
    :raise ConfigurationError: when the redis library is not available
    """
    redis_dependency = limits.util.get_dependency("redis")
    if not redis_dependency:
        raise limits.errors.ConfigurationError(
            "redis prerequisite not available"
        )  # pragma: no cover
    uri = uri.replace("redis+unix", "unix")

    redis_options = options.copy()
    parsed_redis_url = urlparse(uri)

    redis_options.update({
        'host': parsed_redis_url.hostname,
        'port': parsed_redis_url.port,
        'username': parsed_redis_url.username,
        'password': parsed_redis_url.password,
        'ssl': True,
        'ssl_cert_reqs': None
    })

    self.storage = redis.Redis(**redis_options)
    self.initialize_storage(uri)
    super(RedisStorage, self).__init__()


RedisStorage.__init__ = redis_init


logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(thread)d: %(message)s'
)

logger = logging.getLogger("openalex-api-proxy")

libraries_to_mum = []

for library in libraries_to_mum:
    library_logger = logging.getLogger(library)
    library_logger.setLevel(logging.WARNING)
    library_logger.propagate = True
    warnings.filterwarnings("ignore", category=UserWarning, module=library)

Compress(app)
