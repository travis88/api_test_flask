import os
import uuid
import jwt
import datetime
from flask import Flask, json, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

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

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            return jsonify({"message" : "Token is missing"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])            
            current_user = User.query.get(data["id"])
        except: 
            return jsonify({"message" : "Token in invalid"}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route("/user", methods=["GET"])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({"message" : "Cannot perform that function!"})

    users = User.query.all()
    output = [users_dict(user) for user in users]
    return jsonify({"users": output})

@app.route("/user/<user_id>", methods=["GET"])    
@token_required
def get_user(current_user, user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message" : "No user found"})
    return jsonify({"user" : users_dict(user)})

@app.route("/user", methods=["POST"])    
@token_required
def create_user(current_user):
    data = request.get_json()

    hashed_password = generate_password_hash(data["password"], method="sha256")
    new_user = User(name=data["name"], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message" : "New user created"})

@app.route("/user/<user_id>", methods=["PUT"])  
@token_required  
def promote_user(current_user, user_id):
    user: User = User.query.get(user_id)

    if not user:
        return jsonify({"message" : "No user found"})

    user.admin = True 
    db.session.commit()       

    return jsonify({"message" : "User promoted"})

@app.route("/user/<user_id>", methods=["DELETE"]) 
@token_required   
def delete_user(current_user, user_id):
    user: User = User.query.get(user_id)

    if not user:
        return jsonify({"message" : "Not user found"})

    db.session.delete(user)  
    db.session.commit()      
    return jsonify({"message" : "User deleted"})

@app.route("/login", methods=["POST"])    
def login():
    auth = request.authorization
    user = User.query.filter_by(name=auth.username).first()
    
    if check_password_hash(user.password, auth.password):        
        token = jwt.encode({"id" : str(user.id), "exp" : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config["SECRET_KEY"])
        return jsonify({"token" : token.decode("utf-8")})
    
    return make_response("Could not verify", 401, {"WWW-Authenticate" : "Basic realm=\"Login required\""})

def todo_item(todo: Todo):
    return {
        "id" : todo.id,
        "text" : todo.text,
        "complete" : todo.complete,
        "user_id" : todo.user_id
    }

@app.route("/todo", methods=["GET"])
def get_all_todos():
    todos = Todo.query.all()
    output = [todo_item(todo) for todo in todos]
    return jsonify({"todos" : output})

@app.route("/todo/<todo_id>", methods=["GET"])  
@token_required  
def get_todo(current_user, todo_id):
    todo = Todo.query.get(todo_id)

    if not todo:
        return jsonify({"message" : "Todo not found"})

    return jsonify({"todo" : todo_item(todo)})

@app.route("/todo", methods=["POST"])
@token_required
def add_todo(current_user):
    data = request.get_json()
    todo = Todo(text=data["text"], user_id=current_user.id, complete=False)
    db.session.add(todo)
    db.session.commit()
    return jsonify({"message" : "New Todo created"})

@app.route("/todo/<todo_id>", methods=["PUT"])    
@token_required
def update_todo(current_user, todo_id):
    todo: Todo = Todo.query.get(todo_id)
    if not todo:
        return jsonify({"message" : "Todo not found"})

    todo.complete = True
    db.session.commit()
    return jsonify({"message" : "Todo updated"})

@app.route("/todo/<todo_id>", methods=["DELETE"])    
@token_required
def delete_todo(current_user, todo_id):
    todo: Todo = Todo.query.get(todo_id)
    if not todo:
        return jsonify({"message" : "Todo not found"})

    db.session.delete(todo)
    db.session.commit()
    return jsonify({"message" : "Todo deleted"})

if __name__ == "__main__":
    app.run(debug=True)
