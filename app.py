import logging
import sys
import warnings

from flask import Flask
from flask_compress import Compress

app = Flask(__name__)

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
