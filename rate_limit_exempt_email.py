from datetime import datetime, timezone

import shortuuid
from sqlalchemy import Sequence, or_

from app import db


class RateLimitExempt(db.Model):
    id = db.Column(db.BigInteger, Sequence('ratelimit_exempt_id_seq', start=1, increment=1), primary_key=True)
    email = db.Column(db.Text, nullable=False, unique=True)
    created = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc).isoformat())
    active = db.Column(db.Boolean, nullable=False, default=True)
    expires = db.Column(db.DateTime)
    name = db.Column(db.Text)
    zendesk_ticket = db.Column(db.Text)
    notes = db.Column(db.Text)

    def to_dict(self):
        return {
            'email': self.email,
            'created': self.created,
            'active': self.active,
            'expires': self.expires and self.expires.isoformat(),
        }

    def __init__(self, **kwargs):
        self.created = datetime.now(timezone.utc).isoformat()
        self.active = True
        super().__init__(**kwargs)

    def __repr__(self):
        return f'<RateLimitExempt ({self.id}, {self.email})>'


def get_rate_limit_exempt_emails():
    q = RateLimitExempt.query.filter_by(active=True)
    return [item.email for item in q.all()]