import os
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from .models import db, User
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['ENV'] = 'development'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', "sqlite:///database.db")
app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY', "secret-key")

db.init_app(app)
Migrate(app, db) # flask db init, flask db migrate, flask db upgrade, flask db downgrade 
jwt = JWTManager(app)
CORS(app)

@app.route('/')
def main():
    return jsonify({ "msg": "API Flask with JWT"}), 200

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if not username:
        return jsonify({ "msg":"Username is required!"}), 400
    
    if not password:
        return jsonify({ "msg":"Password is required!"}), 400
    
    
    userFound = User.query.filter_by(username=username).first()
    
    if userFound:
        return jsonify({ "msg":"Username already exists!"}), 400
    
    user = User()
    user.username = username
    user.password = generate_password_hash(password)
    user.save()
    
    return jsonify({ "msg": "Register successfully, please start session!!"}), 201
    

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if not username:
        return jsonify({ "msg":"Username is required!"}), 400
    
    if not password:
        return jsonify({ "msg":"Password is required!"}), 400
    
    userFound = User.query.filter_by(username=username).first()
    
    if not userFound:
        return jsonify({ "msg":"Your credentails are incorrects!"}), 401
    
    if not check_password_hash(userFound.password, password):
        return jsonify({ "msg":"Your credentails are incorrects!"}), 401
    
    access_token = create_access_token(identity=userFound.id)
    
    data = {
        "access_token": access_token,
        "user": userFound.serialize()
    }
    
    return jsonify(data), 200


@app.route('/profile', methods=['GET'])
@jwt_required() # aqui indicamos que este endpoint es privado solo lo puede acceder un usuario registrado
def profile():
    id = get_jwt_identity()
    user = User.query.get(id)
    return jsonify({ "msg": "Private Route", "user": user.serialize()}), 200
    


if __name__ == '__main__':
    app.run()