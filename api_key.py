from datetime import datetime, timezone

import shortuuid
from sqlalchemy import Sequence, or_

from app import db


class APIKey(db.Model):
    id = db.Column(db.BigInteger, Sequence('api_keys_id_seq', start=1, increment=1), primary_key=True)
    email = db.Column(db.Text, nullable=False, unique=True)
    key = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc).isoformat())
    active = db.Column(db.Boolean, nullable=False, default=True)
    expires = db.Column(db.DateTime)
    is_demo = db.Column(db.Boolean)

    def to_dict(self, show_key=False):
        return {
            'email': self.email,
            'key': self.key if show_key else '*'*len(self.key),
            'created': self.created,
            'active': self.active,
            'expires': self.expires and self.expires.isoformat(),
            'is_demo': self.is_demo,
        }

    def __init__(self, **kwargs):
        self.created = datetime.now(timezone.utc).isoformat()
        self.active = True
        self.key = shortuuid.uuid()
        super().__init__(**kwargs)

    def __repr__(self):
        return f'<APIKey ({self.email}, {self.key})>'


def valid_key(key):
    return APIKey.query.filter(
        APIKey.key == key,
        APIKey.active == True,
        or_(APIKey.expires == None, APIKey.expires > datetime.now(timezone.utc).isoformat())
    ).first()

def get_all_valid_keys():
    q = APIKey.query.filter(
        APIKey.active == True,
        or_(APIKey.expires == None, APIKey.expires > datetime.now(timezone.utc).isoformat())
    )
    return [item.key for item in q.all()]