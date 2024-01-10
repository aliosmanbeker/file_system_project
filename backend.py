from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt 
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///requests.db'
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class RequestLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), default=str(datetime.utcnow()))  # Convert datetime object to string
    ip_address = db.Column(db.String(15))
    port = db.Column(db.String(10))
    file_name = db.Column(db.String(255))
    file_size = db.Column(db.String(20))
    lines = db.Column(db.String(10))
    created_date = db.Column(db.String(20))
    modified_date = db.Column(db.String(20))
    sum_result = db.Column(db.String(50), nullable=True)
    success = db.Column(db.String(5))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route("/token", methods=["POST"])
def create_token():
    try:
        email = request.json.get("email", None)
        password_hash = request.json.get("password_hash", None)

        # Query your database for username and password
        user = User.query.filter_by(email=email).first()

        if user is None:
            # the user was not found in the database
            return jsonify({"msg": "Bad username or password"}), 401

        # create a new token with the user id inside
        access_token = create_access_token(identity=user.id)
        return jsonify({ "token": access_token, "user_id": user.id })

    except Exception as e:
        # Log the detailed error message
        app.logger.error("Detailed error in create_token endpoint: %s", str(e))

        # Return a generic error message to the client
        return jsonify({"error": "An internal server error occurred. Please try again later."}), 500
    
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        password_hash = data.get('password')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'Bu e-posta adresi zaten kayıtlı'}), 400

        new_user = User(email=email)
        new_user.set_password(password_hash)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'Registration completed successfully. You can log in.'})
    except Exception as e:
        print(f'Hata: {str(e)}')
        return jsonify({'error': str(e)}), 500
    
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password_hash = data.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password_hash):
            access_token = create_access_token(identity=email)
            return jsonify({'message': 'Incorrect email address or password.'})
        else:
            return jsonify({'message': 'Incorrect email address or password.'})

    except Exception as e:
        print(f'Hata: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    return jsonify({"id": user.id, "email": user.email }), 200

@app.route('/history', methods=['GET'])
@jwt_required()
def get_history():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        
        if not user.is_admin:
            return jsonify({'error': 'You must have admin authority for this operation.'}), 403

        history_entries = RequestLog.query.all()
        history_data = []

        for entry in history_entries:
            entry_data = {
                'timestamp': entry.timestamp,
                'ip_address': entry.ip_address,
                'port': entry.port,
                'file_name': entry.file_name,
                'file_size': entry.file_size,
                'lines': entry.lines,
                'created_date': entry.created_date,
                'modified_date': entry.modified_date,
                'sum_result': entry.sum_result,
                'success': entry.success,
            }
            history_data.append(entry_data)

        return jsonify(history_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sum', methods=['POST'])
def calculate_sum():
    try:
        numbers = request.json['numbers']
        result = sum(numbers)

        # Log request details to the database
        log_request(request, result, success=True)

        return jsonify({'sum': result})
    except Exception as e:
        # Log request details to the database in case of an error
        log_request(request, result=None, success=False, error=str(e))
        return jsonify({'error': str(e)}), 400

def log_request(request, result, success, error=None):
    try:
        file = request.files['file']
        file_name = file.filename
        file_size = file.content_length / (1024 * 1024)  # Convert bytes to megabytes

        log_entry = RequestLog(
            ip_address=request.remote_addr,
            port=request.environ.get('REMOTE_PORT'),
            file_name=file_name,
            file_size=file_size,
            lines=len(request.json['numbers']),
            created_date=request.files['file'].last_modified.strftime('%Y-%m-%d'),
            modified_date=request.files['file'].last_modified.strftime('%Y-%m-%d'),
            sum_result=result,
            success=success,
        )

        db.session.add(log_entry)
        db.session.commit()

    except Exception as e:
        print(f"Error logging request: {str(e)}")

@app.route('/save', methods=['POST'])
def save_to_database():
    try:
        data = request.json
        file_info = data['fileInfo']
        sum_result = data['sumResult']
        success = data['success']

        log_entry = RequestLog(
            ip_address=request.remote_addr,
            port=int(request.environ.get('REMOTE_PORT')),  
            file_name=file_info['fileName'],
            file_size=float(file_info['fileSize']),  
            lines=file_info['lines'],
            created_date=file_info['createdDate'],
            modified_date=file_info['modifiedDate'],
            sum_result=sum_result,
            success=success,
        )

        db.session.add(log_entry)
        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        print(f"Error saving to database: {str(e)}")
        return jsonify({'success': False}), 500
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables before running the app

    app.run(debug=True)