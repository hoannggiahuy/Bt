
from flask import Flask, render_template, request, jsonify, session, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import hashlib
import os
import json
import datetime
import uuid
import threading
import time
from werkzeug.utils import secure_filename
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global storage for demonstration
server_storage = {
    'messages': [],
    'logs': [],
    'public_keys': {},
    'session_keys': {},
    'files': {},
    'connected_clients': {},
    'active_sessions': {}
}

class CryptoUtils:
    @staticmethod
    def generate_rsa_keypair():
        """Generate RSA keypair with 2048-bit for better security"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048  # Increased from 1024 for better security
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    @staticmethod
    def serialize_private_key(private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    
    @staticmethod
    def deserialize_public_key(pem_data):
        return serialization.load_pem_public_key(pem_data.encode())
    
    @staticmethod
    def deserialize_private_key(pem_data):
        return serialization.load_pem_private_key(pem_data.encode(), password=None)
    
    @staticmethod
    def rsa_encrypt(data, public_key):
        try:
            # Split data into chunks if too large
            max_chunk_size = public_key.key_size // 8 - 2 * hashes.SHA512().digest_size - 2
            
            if len(data) <= max_chunk_size:
                return public_key.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA512()),
                        algorithm=hashes.SHA512(),
                        label=None
                    )
                )
            else:
                # For larger data, encrypt in chunks
                encrypted_chunks = []
                for i in range(0, len(data), max_chunk_size):
                    chunk = data[i:i + max_chunk_size]
                    encrypted_chunk = public_key.encrypt(
                        chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA512()),
                            algorithm=hashes.SHA512(),
                            label=None
                        )
                    )
                    encrypted_chunks.append(encrypted_chunk)
                return b''.join(encrypted_chunks)
        except Exception as e:
            raise Exception(f"RSA encryption failed: {str(e)}")
    
    @staticmethod
    def rsa_decrypt(encrypted_data, private_key):
        try:
            chunk_size = private_key.key_size // 8
            
            if len(encrypted_data) <= chunk_size:
                return private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA512()),
                        algorithm=hashes.SHA512(),
                        label=None
                    )
                )
            else:
                # Decrypt chunks
                decrypted_chunks = []
                for i in range(0, len(encrypted_data), chunk_size):
                    chunk = encrypted_data[i:i + chunk_size]
                    decrypted_chunk = private_key.decrypt(
                        chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA512()),
                            algorithm=hashes.SHA512(),
                            label=None
                        )
                    )
                    decrypted_chunks.append(decrypted_chunk)
                return b''.join(decrypted_chunks)
        except Exception as e:
            raise Exception(f"RSA decryption failed: {str(e)}")
    
    @staticmethod
    def rsa_sign(data, private_key):
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
    
    @staticmethod
    def rsa_verify(signature, data, public_key):
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            return True
        except:
            return False
    
    @staticmethod
    def generate_session_key():
        return AESGCM.generate_key(bit_length=256)
    
    @staticmethod
    def aes_gcm_encrypt(data, key):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        # Split ciphertext and tag (last 16 bytes)
        cipher_only = ciphertext[:-16]
        tag = ciphertext[-16:]
        return nonce, cipher_only, tag
    
    @staticmethod
    def aes_gcm_decrypt(nonce, ciphertext, tag, key):
        aesgcm = AESGCM(key)
        # Combine ciphertext and tag
        full_ciphertext = ciphertext + tag
        return aesgcm.decrypt(nonce, full_ciphertext, None)
    
    @staticmethod
    def sha512_hash(data):
        return hashlib.sha512(data).hexdigest()

class LogManager:
    @staticmethod
    def add_log(action, details=None):
        log_entry = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.datetime.now().isoformat(),
            'action': action,
            'details': details or {}
        }
        server_storage['logs'].append(log_entry)
        
        # Emit log to all connected clients
        socketio.emit('new_log', log_entry, to='broadcast')
        return log_entry

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sender')
def sender():
    return render_template('sender.html')

@app.route('/server')
def server():
    return render_template('server.html')

@app.route('/receiver')
def receiver():
    return render_template('receiver.html')

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    server_storage['connected_clients'][request.sid] = {
        'connected_at': datetime.datetime.now().isoformat(),
        'role': None
    }
    emit('connection_status', {'status': 'connected', 'sid': request.sid})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')
    if request.sid in server_storage['connected_clients']:
        del server_storage['connected_clients'][request.sid]

@socketio.on('join_role')
def handle_join_role(data):
    role = data['role']
    join_room(role)
    server_storage['connected_clients'][request.sid]['role'] = role
    emit('joined_role', {'role': role, 'sid': request.sid})
    
    LogManager.add_log('client_joined', {
        'role': role,
        'sid': request.sid
    })

@socketio.on('generate_keys')
def handle_generate_keys(data):
    try:
        role = data['role']
        private_key, public_key = CryptoUtils.generate_rsa_keypair()
        
        # Store keys in session
        session[f'{role}_private_key'] = CryptoUtils.serialize_private_key(private_key)
        session[f'{role}_public_key'] = CryptoUtils.serialize_public_key(public_key)
        
        public_key_pem = CryptoUtils.serialize_public_key(public_key)
        server_storage['public_keys'][role] = public_key_pem
        
        emit('keys_generated', {
            'success': True,
            'public_key': public_key_pem,
            'role': role
        })
        
        # Broadcast to server room
        socketio.emit('key_exchange', {
            'role': role,
            'public_key': public_key_pem,
            'action': 'key_generated'
        }, room='server')
        
        LogManager.add_log('keys_generated', {
            'role': role,
            'key_size': '2048-bit'
        })
        
    except Exception as e:
        emit('error', {'message': f'Lỗi tạo khóa: {str(e)}'})

@socketio.on('handshake')
def handle_handshake(data):
    try:
        action = data['action']
        from_role = data['from']
        to_role = data['to']
        message = data['message']
        
        # Forward message to target role
        socketio.emit('handshake_received', {
            'action': action,
            'from': from_role,
            'message': message,
            'timestamp': datetime.datetime.now().isoformat()
        }, room=to_role)
        
        # Log to server
        socketio.emit('message_forwarded', {
            'type': 'handshake',
            'from': from_role,
            'to': to_role,
            'message': message,
            'timestamp': datetime.datetime.now().isoformat()
        }, room='server')
        
        LogManager.add_log('handshake', {
            'action': action,
            'from': from_role,
            'to': to_role,
            'message': message
        })
        
        emit('handshake_sent', {'success': True, 'action': action})
        
    except Exception as e:
        emit('error', {'message': f'Lỗi handshake: {str(e)}'})

@socketio.on('send_auth_key')
def handle_send_auth_key(data):
    try:
        filename = data.get('filename', 'report.txt')
        
        # Get sender's private key
        sender_private_key_pem = session.get('sender_private_key')
        if not sender_private_key_pem:
            emit('error', {'message': 'Chưa tạo khóa cho người gửi'})
            return
        
        sender_private_key = CryptoUtils.deserialize_private_key(sender_private_key_pem)
        
        # Get receiver's public key
        receiver_public_key_pem = server_storage['public_keys'].get('receiver')
        if not receiver_public_key_pem:
            emit('error', {'message': 'Không tìm thấy khóa công khai của người nhận'})
            return
        
        receiver_public_key = CryptoUtils.deserialize_public_key(receiver_public_key_pem)
        
        # Create metadata
        transaction_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now().isoformat()
        metadata = f"{filename}|{timestamp}|{transaction_id}"
        
        # Sign metadata
        signature = CryptoUtils.rsa_sign(metadata.encode(), sender_private_key)
        
        # Generate and encrypt session key
        session_key = CryptoUtils.generate_session_key()
        encrypted_session_key = CryptoUtils.rsa_encrypt(session_key, receiver_public_key)
        
        # Store session key
        server_storage['session_keys'][transaction_id] = session_key
        server_storage['active_sessions'][transaction_id] = {
            'sender_sid': request.sid,
            'created_at': timestamp,
            'metadata': metadata
        }
        
        # Send to receiver
        socketio.emit('auth_key_received', {
            'metadata': metadata,
            'signature': base64.b64encode(signature).decode(),
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
            'transaction_id': transaction_id,
            'timestamp': timestamp
        }, room='receiver')
        
        # Log to server
        socketio.emit('auth_key_forwarded', {
            'transaction_id': transaction_id,
            'metadata': metadata,
            'timestamp': timestamp
        }, room='server')
        
        LogManager.add_log('auth_key_exchange', {
            'transaction_id': transaction_id,
            'filename': filename,
            'from': 'sender',
            'to': 'receiver'
        })
        
        emit('auth_key_sent', {
            'success': True,
            'transaction_id': transaction_id,
            'metadata': metadata
        })
        
    except Exception as e:
        emit('error', {'message': f'Lỗi gửi khóa xác thực: {str(e)}'})
        LogManager.add_log('auth_key_error', {
            'error': str(e),
            'from': 'sender'
        })

@socketio.on('send_file')
def handle_send_file(data):
    try:
        transaction_id = data.get('transaction_id')
        file_content = data.get('file_content')
        file_name = data.get('file_name', 'report.txt')
        
        if not file_content:
            emit('error', {'message': 'Không có nội dung file'})
            return
        
        # Get session key
        session_key = server_storage['session_keys'].get(transaction_id)
        if not session_key:
            emit('error', {'message': 'Không tìm thấy session key'})
            return
        
        # Get sender's private key for signing
        sender_private_key_pem = session.get('sender_private_key')
        sender_private_key = CryptoUtils.deserialize_private_key(sender_private_key_pem)
        
        # Convert file content to bytes if it's a string
        if isinstance(file_content, str):
            file_bytes = file_content.encode('utf-8')
        else:
            file_bytes = file_content
        
        # Encrypt file with AES-GCM
        nonce, ciphertext, tag = CryptoUtils.aes_gcm_encrypt(file_bytes, session_key)
        
        # Calculate hash
        hash_data = nonce + ciphertext + tag
        file_hash = CryptoUtils.sha512_hash(hash_data)
        
        # Sign the hash
        signature = CryptoUtils.rsa_sign(file_hash.encode(), sender_private_key)
        
        # Create packet
        packet = {
            'nonce': base64.b64encode(nonce).decode(),
            'cipher': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'hash': file_hash,
            'sig': base64.b64encode(signature).decode(),
            'transaction_id': transaction_id,
            'file_name': file_name,
            'file_size': len(file_bytes)
        }
        
        # Store file info
        server_storage['files'][transaction_id] = {
            'name': file_name,
            'size': len(file_bytes),
            'sent_at': datetime.datetime.now().isoformat()
        }
        
        # Send to receiver
        socketio.emit('encrypted_file_received', {
            'packet': packet,
            'timestamp': datetime.datetime.now().isoformat()
        }, room='receiver')
        
        # Log to server
        socketio.emit('file_forwarded', {
            'transaction_id': transaction_id,
            'file_name': file_name,
            'file_size': len(file_bytes),
            'timestamp': datetime.datetime.now().isoformat()
        }, room='server')
        
        LogManager.add_log('file_transfer', {
            'transaction_id': transaction_id,
            'file_name': file_name,
            'file_size': len(file_bytes),
            'from': 'sender',
            'to': 'receiver'
        })
        
        emit('file_sent', {
            'success': True,
            'transaction_id': transaction_id,
            'file_name': file_name
        })
        
    except Exception as e:
        emit('error', {'message': f'Lỗi gửi file: {str(e)}'})
        LogManager.add_log('file_transfer_error', {
            'transaction_id': transaction_id,
            'error': str(e)
        })

@socketio.on('verify_and_decrypt')
def handle_verify_and_decrypt(data):
    try:
        packet = data.get('packet')
        metadata = data.get('metadata')
        signature_b64 = data.get('signature')
        transaction_id = data.get('transaction_id')
        
        # Get receiver's private key
        receiver_private_key_pem = session.get('receiver_private_key')
        if not receiver_private_key_pem:
            emit('error', {'message': 'Chưa tạo khóa cho người nhận'})
            return
        
        receiver_private_key = CryptoUtils.deserialize_private_key(receiver_private_key_pem)
        
        # Get sender's public key
        sender_public_key_pem = server_storage['public_keys'].get('sender')
        sender_public_key = CryptoUtils.deserialize_public_key(sender_public_key_pem)
        
        # Verify metadata signature
        signature = base64.b64decode(signature_b64)
        if not CryptoUtils.rsa_verify(signature, metadata.encode(), sender_public_key):
            raise Exception('Xác thực chữ ký metadata thất bại')
        
        # Get session key
        session_key = server_storage['session_keys'].get(transaction_id)
        if not session_key:
            raise Exception('Không tìm thấy session key')
        
        # Decode packet data
        nonce = base64.b64decode(packet['nonce'])
        ciphertext = base64.b64decode(packet['cipher'])
        tag = base64.b64decode(packet['tag'])
        received_hash = packet['hash']
        file_signature = base64.b64decode(packet['sig'])
        file_name = packet.get('file_name', 'report.txt')
        
        # Verify hash
        hash_data = nonce + ciphertext + tag
        calculated_hash = CryptoUtils.sha512_hash(hash_data)
        
        if received_hash != calculated_hash:
            raise Exception('Xác thực hash thất bại')
        
        # Verify file signature
        if not CryptoUtils.rsa_verify(file_signature, received_hash.encode(), sender_public_key):
            raise Exception('Xác thực chữ ký file thất bại')
        
        # Decrypt file
        decrypted_content = CryptoUtils.aes_gcm_decrypt(nonce, ciphertext, tag, session_key)
        
        # Save decrypted file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"decrypted_{file_name}")
        with open(file_path, 'wb') as f:
            f.write(decrypted_content)
        
        # Send ACK to sender
        socketio.emit('verification_result', {
            'type': 'ACK',
            'message': 'File đã được xác thực và giải mã thành công',
            'transaction_id': transaction_id,
            'timestamp': datetime.datetime.now().isoformat()
        }, room='sender')
        
        # Log success
        LogManager.add_log('file_verified_success', {
            'transaction_id': transaction_id,
            'file_name': file_name,
            'status': 'SUCCESS'
        })
        
        emit('verification_success', {
            'success': True,
            'decrypted_content': decrypted_content.decode('utf-8'),
            'file_name': file_name,
            'message': 'File đã được xác thực và giải mã thành công'
        })
        
    except Exception as e:
        # Send NACK to sender
        socketio.emit('verification_result', {
            'type': 'NACK',
            'message': f'Lỗi integrity: {str(e)}',
            'transaction_id': transaction_id,
            'timestamp': datetime.datetime.now().isoformat()
        }, room='sender')
        
        # Log failure
        LogManager.add_log('file_verification_failed', {
            'transaction_id': transaction_id,
            'status': 'FAILED',
            'error': str(e)
        })
        
        emit('error', {'message': f'Xác thực thất bại: {str(e)}'})

# API Routes for backward compatibility
@app.route('/api/get_logs')
def get_logs():
    return jsonify({'logs': server_storage['logs']})

@app.route('/api/get_stats')
def get_stats():
    success_count = len([log for log in server_storage['logs'] if log.get('details', {}).get('status') == 'SUCCESS'])
    failed_count = len([log for log in server_storage['logs'] if log.get('details', {}).get('status') == 'FAILED'])
    
    return jsonify({
        'total_logs': len(server_storage['logs']),
        'success_count': success_count,
        'failed_count': failed_count,
        'connected_clients': len(server_storage['connected_clients']),
        'active_sessions': len(server_storage['active_sessions'])
    })

if __name__ == '__main__':
    print("🚀 Digital Signature System đang khởi động...")
    print("📡 Server chạy tại: http://0.0.0.0:5000")
    print("🔐 Hỗ trợ: RSA-2048, AES-GCM, SHA-512")
    print("📁 Upload thư mục: uploads/")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
