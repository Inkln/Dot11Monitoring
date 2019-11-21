from ..app import db


class AP(db.Model):
    __tablename__ = 'aps'
    ap_mac = db.Column(db.String(32), primary_key=True, unique=True)
    workspace = db.Column(db.String(256), index=True)

    essid = db.Column(db.String(256), index=True)
    channel = db.Column(db.Integer, index=True)
    privacy = db.Column(db.String(8), index=True)
    comment = db.Column(db.String(1024), nullable=True)

    authorisation = db.relationship("Auth", backref='ap')
    transfer = db.relationship("DataTransfer", backref='ap')

    def __repr__(self):
        return '<Ap {}:{}>'.format(self.ap_mac, self.essid)


class Client(db.Model):
    __tablename__ = 'clients'
    client_mac = db.Column(db.String(32), primary_key=True, unique=True)
    workspace = db.Column(db.String(256), index=True)

    mac_vendor = db.Column(db.String(256), nullable=True)
    comment = db.Column(db.String(1024), nullable=True)

    authorisation = db.relationship("Auth", backref='client')
    transfer = db.relationship("DataTransfer", backref='client')

    def __repr__(self):
        return '<Client {}>'.format(self.client_mac)

class Auth(db.Model):
    __tablename__ = 'authorisations'
    ap_mac = db.Column(db.String(32), db.ForeignKey('aps.ap_mac'), primary_key=True)
    client_mac = db.Column(db.String(32), db.ForeignKey('clients.client_mac'), primary_key=True)
    workspace = db.Column(db.String(256), index=True)

    stage = db.Column(db.Integer)
    tries = db.Column(db.Integer)

    ap = db.relationship("Ap", backref="authorisation")
    client = db.relationship("Client", backref="authorisation")

    def __repr__(self):
        return '<Auth {}>'.format(self.ap_mac, self.client_mac)


class DataTransfer(db.Model):
    ap_mac = db.Column(db.String(32), db.ForeignKey('aps.ap_mac'), primary_key=True)
    client_mac = db.Column(db.String(32), db.ForeignKey('clients.client_mac'), primary_key=True)
    workspace = db.Column(db.String(256), index=True)

    bytes = db.Column(db.Integer)

    ap = db.relationship("Ap", backref="transfer")
    client = db.relationship("Client", backref="transfer")

    def __repr__(self):
        return '<Transfer from {} to >'.format(self.ap_mac, self.client_mac)