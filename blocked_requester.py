import datetime

from sqlalchemy import Sequence

from app import db


class BlockedRequester(db.Model):
    id = db.Column(db.Integer, Sequence('blocked_requester_id_seq', start=1, increment=1), primary_key=True)
    ip = db.Column(db.Text)
    email = db.Column(db.Text)
    blocked_from = db.Column(db.DateTime)
    blocked_until = db.Column(db.DateTime)
    notes = db.Column(db.Text)

    def to_dict(self, show_key=False):
        return {
            'ip': self.ip,
            'email': self.email,
            'blocked_from': self.blocked_from and self.blocked_from.isoformat(),
            'blocked_until': self.blocked_until,
            'notes': self.notes,
        }

    def __repr__(self):
        return f'<BlockedRequester ({self.ip}, {self.email})>'


_blocked_requesters_by_ip = {}
_blocked_requesters_by_email = {}

for blocked_requester in BlockedRequester.query.all():
    if blocked_requester.ip:
        _blocked_requesters_by_ip[blocked_requester.ip] = blocked_requester
    if blocked_requester.email:
        _blocked_requesters_by_email[blocked_requester.email] = blocked_requester


def check_for_blocked_requester(request_ip, request_email):
    block = _blocked_requesters_by_ip.get(request_ip) or _blocked_requesters_by_email.get(request_email)
    if (
        block
        and (block.blocked_from is None or block.blocked_from < datetime.datetime.utcnow())
        and (block.blocked_until is None or block.blocked_until > datetime.datetime.utcnow())
    ):
        return block
    else:
        return None
