from flask import Flask, request, jsonify
from model import db, User
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_ngrok import run_with_ngrok
from flask_bcrypt import Bcrypt
from flask_mail import Mail 
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
import string
import random



app = Flask(__name__)
run_with_ngrok(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'jatinmathur1157@gmail.com'
app.config['MAIL_PASSWORD'] = 'exgxwbiykhostjep'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
db.init_app(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
mail.init_app(app)


password_reset_tokens = {}


@app.route("/register", methods=['POST'])
def register_user():
    data = request.json
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone_no = data.get('phone_no')
    password = data.get('password')
    if not all([email, first_name, last_name, phone_no, password]):
        return jsonify({'error': 'All fields need to be provided'})
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User with this email already exists'})
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, first_name=first_name, last_name=last_name,
                    phone_no=phone_no, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(phone_no=data['phone_no']).first()
    if not user:
        return jsonify({'message': 'User not found'})
    if bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'first_name': user.first_name,'last_name' : user.last_name, 'email': user.email , 'phone_no' : user.phone_no})
        return jsonify({'access_token': access_token})
    else:
        return jsonify({'message': 'Invalid credentials'})

@app.route('/retrieve/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({'user_id': user.user_id, 'first_name': user.first_name, 'last_name': user.last_name, 'phone_no': user.phone_no, 'email': user.email})
    else:
        return jsonify({'message': 'User not found'})

@app.route("/update/<int:user_id>", methods=['PUT'])
@jwt_required()
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'})
    data = request.json
    user.email = data.get('email', user.email)
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.phone_no = data.get('phone_no', user.phone_no)
    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

@app.route("/delete/<int:user_id>", methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})



@app.route("/change_password/<int:user_id>", methods=['POST'])
@jwt_required()
def change_password(user_id):
    phone_no = get_jwt_identity()  
    data = request.json
    password = data.get('password')
    new_password = data.get('new_password')
    user = User.query.filter_by(phone_no=phone_no).first()
    if not user:
        return jsonify({'message': 'User not found'})
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Incorrect password'})
    if not new_password:
        return jsonify({'message': 'New password not provided'})
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user.password = hashed_password()
    db.session.commit()
    return jsonify({'message': 'Password changed successfully'})

@app.route('/forget', methods=['POST'])
def forget_password():
    data = request.json
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'message': 'User not found'})
    else:
        token = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=10))
        send_reset_password_email = token 
        reset_link = f'http://127.0.0.1:5000/reset?token={token}'
        
        msg = Message(
            'Password Reset Link',
            sender='jatinmathur1157@gmail.com',
            recipients=[email]
        )
        msg.body = f'Hello,\n\nYour reset link is: {reset_link}'
        mail.send(msg)
        
        return jsonify({'message': 'Password reset link sent successfully'})

def send_reset_password_email(user_email, reset_link):
    msg = Message('Reset Your Password', sender='jatinmathur1157@gmail.com', recipients=[user_email])
    msg.body = f'Reset your password: {reset_link}'
    mail.send(msg)

@app.route('/reset/<token>', methods=['POST'])
def reset():
    data = request.json
    new_password = data.get('new_password')
    email = data.get('email')
      

    if not new_password or not email :
        return jsonify({'message': 'Missing required information. Please provide new_password, email, and token.'})

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Invalid or expired token. Please request a new password reset.'})

    user.password = generate_password_hash(new_password)
    
    db.session.commit()
    return jsonify({'message': 'Password reset successful'})

if __name__ == '__main__':
     with app.app_context():
        db.create_all()
        app.run()


