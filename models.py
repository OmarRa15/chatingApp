from flask_login import UserMixin
from app import db


class Users(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(15),nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_confirmed = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return 'ID: ' + str(self.id) + ' ' + self.first_name + ' ' + self.last_name
