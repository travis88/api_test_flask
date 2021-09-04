import os
import uuid
from flask import Flask, json, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

migrate = Migrate(app, db)

class User(db.Model):
    __tablename__ = "cd_users"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column("c_name", db.String(50))
    password = db.Column("c_password", db.String(100))
    admin = db.Column("b_admin", db.Boolean)

class Todo(db.Model):
    __tablename__ = "cd_todos"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    text = db.Column("c_text", db.String(50))
    complete = db.Column("b_complete", db.Boolean)
    user_id = db.Column("f_user", UUID(as_uuid=True))

def users_dict(user: User):
    data = {
        "id": user.id,
        "name": user.name,
        "password": user.password,
        "admin": user.admin
    }    
    return data

@app.route("/user", methods=["GET"])
def get_all_users():
    users = User.query.all()
    output = [users_dict(user) for user in users]
    return jsonify({"users": output})

@app.route("/user/<user_id>", methods=["GET"])    
def get_user(user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message" : "No user found"})
    return jsonify({"user" : users_dict(user)})

@app.route("/user", methods=["POST"])    
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data["password"], method="sha256")
    new_user = User(name=data["name"], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message" : "New user created"})

@app.route("/user/<user_id>", methods=["PUT"])    
def promote_user(user_id):
    user: User = User.query.get(user_id)

    if not user:
        return jsonify({"message" : "No user found"})

    user.admin = True 
    db.session.commit()       

    return jsonify({"message" : "User promoted"})

@app.route("/user/<user_id>", methods=["DELETE"])    
def delete_user(user_id):
    user: User = User.query.get(user_id)

    if not user:
        return jsonify({"message" : "Not user found"})

    db.session.delete(user)  
    db.session.commit()      
    return jsonify({"message" : "User deleted"})

if __name__ == "__main__":
    app.run(debug=True)
