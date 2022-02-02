import logging
import os
import sys
import warnings
from urllib.parse import urlparse

import bmemcached
import limits.errors
import limits.util
import redis
from flask import Flask
from flask_compress import Compress
from flask_sqlalchemy import SQLAlchemy
from limits.storage.redis import RedisStorage
from sqlalchemy.pool import NullPool

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(thread)d: %(message)s'
)

logger = logging.getLogger("openalex-api-proxy")

libraries_to_mum = [
    'psycopg2',
]

for library in libraries_to_mum:
    library_logger = logging.getLogger(library)
    library_logger.setLevel(logging.WARNING)
    library_logger.propagate = True
    warnings.filterwarnings("ignore", category=UserWarning, module=library)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL').replace('postgres://', 'postgresql://')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['RATELIMIT_HEADERS_ENABLED'] = os.getenv('RATELIMIT_HEADERS_ENABLED')
app.config['RATELIMIT_STORAGE_URL'] = os.getenv('REDIS_URL')
app.config['SQLALCHEMY_ECHO'] = (os.getenv('SQLALCHEMY_ECHO', False) == 'True')
app.config['RATELIMIT_HEADER_RETRY_AFTER_VALUE'] = 'http-date'
app.config['RATELIMIT_IN_MEMORY_FALLBACK_ENABLED'] = True
app.config['RATELIMIT_IN_MEMORY_FALLBACK'] = '100000/day'

slice_and_dice_api = os.getenv('SLICE_AND_DICE_API_URL')
entity_api = os.getenv('ENTITY_API_URL')
formatter_api = os.getenv('FORMATTED_ELASTIC_URL')


class NullPoolSQLAlchemy(SQLAlchemy):
    def apply_driver_hacks(self, flask_app, info, options):
        options['poolclass'] = NullPool
        return super(NullPoolSQLAlchemy, self).apply_driver_hacks(flask_app, info, options)


db = NullPoolSQLAlchemy(app, session_options={"autoflush": False})

Compress(app)


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

memcached_servers = os.environ.get('MEMCACHEDCLOUD_SERVERS').split(',')
memcached_user = os.environ.get('MEMCACHEDCLOUD_USERNAME')
memcached_password = os.environ.get('MEMCACHEDCLOUD_PASSWORD')

memcached = bmemcached.Client(memcached_servers, memcached_user, memcached_password)
