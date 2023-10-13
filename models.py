from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Users(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), index=True, unique=True)
    email = db.Column(db.String(150), index=True, unique=True)
    password = db.Column(db.String(255), index=True, unique=True)


class Books(db.Model):
    __tablename__ = "tblbook"
    bookid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), index=True, unique=True)
    picture = db.Column(db.String(150), index=True, unique=True)
    isbn = db.Column(db.String(255), index=True, unique=True)
