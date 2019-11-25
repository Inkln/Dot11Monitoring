from ..app import db


# auth models
class User(db.Model):
    username = db.Column(db.String(128), primary_key=True, unique=True)
    email = db.Column(db.String(256), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)

    is_collector = db.Column(db.Boolean, default=False)
    is_viewer = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)


# dot11 models
class Auth(db.Model):
    ap_mac = db.Column(db.String(32), db.ForeignKey('ap.ap_mac'), primary_key=True)
    client_mac = db.Column(db.String(32), db.ForeignKey('client.client_mac'), primary_key=True)
    workspace = db.Column(db.String(256), primary_key=True)

    stage = db.Column(db.Integer)
    tries = db.Column(db.Integer)

    # ap = db.relationship(Ap, backref="auth")
    # client = db.relationship(Client, backref="auth")

    def __repr__(self):
        return '<Auth {}>'.format(self.ap_mac, self.client_mac)


class DataTransfer(db.Model):
    ap_mac = db.Column(db.String(32), db.ForeignKey('ap.ap_mac'), primary_key=True)
    client_mac = db.Column(db.String(32), db.ForeignKey('client.client_mac'), primary_key=True)
    workspace = db.Column(db.String(256), primary_key=True)

    bytes = db.Column(db.Integer)

    # ap = db.relationship("Ap", backref="transfer")
    # client = db.relationship("Client", backref="transfer")

    def __repr__(self):
        return '<Transfer from {} to >'.format(self.ap_mac, self.client_mac)


class Ap(db.Model):
    # __tablename__ = 'aps'
    ap_mac = db.Column(db.String(32), primary_key=True, unique=True)
    workspace = db.Column(db.String(256), primary_key=True)

    essid = db.Column(db.String(256), index=True)
    channel = db.Column(db.Integer, index=True)
    privacy = db.Column(db.String(8), index=True)
    comment = db.Column(db.String(1024), nullable=True)

    auths = db.relationship(Auth, backref='aps', lazy='dynamic')
    transfers = db.relationship(DataTransfer, backref='aps', lazy='dynamic')

    def __repr__(self):
        return '<Ap {}:{}>'.format(self.ap_mac, self.essid)


class Client(db.Model):
    # __tablename__ = 'clients'
    client_mac = db.Column(db.String(32), primary_key=True, unique=True)
    workspace = db.Column(db.String(256), primary_key=True)

    mac_vendor = db.Column(db.String(256), nullable=True)
    comment = db.Column(db.String(1024), nullable=True)

    auths = db.relationship(Auth, backref='clients', lazy='dynamic')
    transfers = db.relationship(DataTransfer, backref='clients', lazy='dynamic')

    def __repr__(self):
        return '<Client {}>'.format(self.client_mac)
