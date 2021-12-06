import datetime

import shortuuid
from sqlalchemy import Sequence

from app import db


class APIKey(db.Model):
    id = db.Column(db.BigInteger, Sequence('api_keys_id_seq', start=1, increment=1), primary_key=True)
    email = db.Column(db.Text, nullable=False)
    key = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, nullable=False)

    def to_dict(self, show_key=False):
        return {
            'email': self.email,
            'key': self.key if show_key else '*'*len(self.key),
            'created': self.created,
            'active': self.active
        }

    def __init__(self, **kwargs):
        self.created = datetime.datetime.utcnow()
        self.active = True
        self.key = shortuuid.uuid()
        super().__init__(**kwargs)

    def __repr__(self):
        return f'<APIKey ({self.email}, {self.key})>'
