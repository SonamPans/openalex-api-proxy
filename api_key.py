import datetime

import shortuuid
from sqlalchemy import Sequence

from app import db
import datetime


class APIKey(db.Model):
    id = db.Column(db.BigInteger, Sequence('api_keys_id_seq', start=1, increment=1), primary_key=True)
    email = db.Column(db.Text, nullable=False, unique=True)
    key = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    active = db.Column(db.Boolean, nullable=False, default=True)
    expires = db.Column(db.DateTime)

    def to_dict(self, show_key=False):
        return {
            'email': self.email,
            'key': self.key if show_key else '*'*len(self.key),
            'created': self.created,
            'active': self.active,
            'expires': self.expires and self.expires.isoformat()
        }

    def __init__(self, **kwargs):
        self.created = datetime.datetime.utcnow()
        self.active = True
        self.key = shortuuid.uuid()
        super().__init__(**kwargs)

    def __repr__(self):
        return f'<APIKey ({self.email}, {self.key})>'
