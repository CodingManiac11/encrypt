from flask import Flask, request, jsonify, render_template, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime
import jwt
import os
from dotenv import load_dotenv
import base64

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='threading')

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    messages_sent = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    messages_received = db.relationship('Message', backref='recipient', lazy=True, foreign_keys='Message.recipient_id')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)  # Encrypted content
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='sent')  # sent, delivered, read

# Create database tables
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")

# Helper Functions
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode(), public_pem.decode()

def encrypt_message(message, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(encrypted_message_b64, private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    encrypted_message = base64.b64decode(encrypted_message_b64.encode('utf-8'))
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        print(f"Registration attempt for username: {username}")  # Debug log
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        private_key, public_key = generate_key_pair()
        
        user = User(
            username=username,
            password=password,
            public_key=public_key,
            private_key=private_key
        )
        
        db.session.add(user)
        db.session.commit()
        print(f"User {username} registered successfully")  # Debug log
        
        token = jwt.encode({'user_id': user.id}, app.config['SECRET_KEY'])
        return jsonify({
            'token': token,
            'username': username,
            'public_key': public_key
        })
    except Exception as e:
        print(f"Registration error: {str(e)}")  # Debug log
        db.session.rollback()
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.password != password:
        return jsonify({'error': 'Invalid password'}), 401
    
    token = jwt.encode({'user_id': user.id}, app.config['SECRET_KEY'])
    return jsonify({
        'token': token,
        'username': username,
        'public_key': user.public_key,
        'private_key': user.private_key
    })

@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'public_key': user.public_key
    } for user in users])

@app.route('/messages', methods=['GET'])
def get_messages():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'No token provided'}), 401
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    
    messages = Message.query.filter(
        (Message.sender_id == user_id) | (Message.recipient_id == user_id)
    ).order_by(Message.timestamp).all()
    
    user = User.query.get(user_id)
    
    return jsonify([{
        'id': msg.id,
        'content': msg.content,
        'sender': msg.sender.username,
        'recipient': msg.recipient.username,
        'timestamp': msg.timestamp.isoformat(),
        'status': msg.status,
        'encrypted': True
    } for msg in messages])

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    token = request.args.get('token')
    if not token:
        return False
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        user = User.query.get(user_id)
        if user:
            join_room(f'user_{user_id}')
            return True
    except:
        return False

@socketio.on('send_message')
def handle_message(data):
    token = data.get('token')
    if not token:
        return
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        sender_id = payload['user_id']
        recipient_id = data.get('recipient_id')
        content = data.get('content')
        
        sender = User.query.get(sender_id)
        recipient = User.query.get(recipient_id)
        
        if not sender or not recipient:
            return
        
        # Encrypt message with recipient's public key
        encrypted_content = encrypt_message(content, recipient.public_key)
        
        # Store message in database
        message = Message(
            content=encrypted_content,
            sender_id=sender_id,
            recipient_id=recipient_id
        )
        db.session.add(message)
        db.session.commit()
        
        # Emit to recipient with encrypted content (client will decrypt)
        emit('new_message', {
            'id': message.id,
            'content': encrypted_content,
            'sender': sender.username,
            'timestamp': message.timestamp.isoformat(),
            'status': message.status
        }, room=f'user_{recipient_id}')
        
        # Emit to sender with encrypted content
        emit('message_sent', {
            'id': message.id,
            'content': encrypted_content,
            'recipient': recipient.username,
            'timestamp': message.timestamp.isoformat(),
            'status': message.status
        }, room=f'user_{sender_id}')
        
    except Exception as e:
        print(f"Error sending message: {str(e)}")

@socketio.on('typing')
def handle_typing(data):
    token = data.get('token')
    if not token:
        return
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        sender_id = payload['user_id']
        recipient_id = data.get('recipient_id')
        
        sender = User.query.get(sender_id)
        if sender:
            emit('user_typing', {
                'username': sender.username
            }, room=f'user_{recipient_id}')
    except:
        pass

@socketio.on('message_read')
def handle_message_read(data):
    token = data.get('token')
    if not token:
        return
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        message_id = data.get('message_id')
        
        message = Message.query.get(message_id)
        if message and message.recipient_id == user_id:
            message.status = 'read'
            db.session.commit()
            
            emit('message_status', {
                'message_id': message_id,
                'status': 'read'
            }, room=f'user_{message.sender_id}')
    except:
        pass

if __name__ == '__main__':
    socketio.run(app, debug=True, port=8080) 
    