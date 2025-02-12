# # from flask import Flask, jsonify
# # from flask_cors import CORS
# # import psycopg2

# # app = Flask(__name__)
# # CORS(app)  # Enable CORS for all routes

# # # Database connection
# # def get_db_connection():
# #     conn = psycopg2.connect(
# #         host='localhost',
# #         database='mineLocation',
# #         user='postgres',
# #         password='1234'
# #     )
# #     return conn

# # # Root endpoint for testing purposes
# # @app.route('/', methods=['GET'])
# # def index():
# #     return "Welcome to the Locations API!"
 


# # # API endpoint to fetch locations
# # @app.route('/locations', methods=['GET'])
# # def get_locations():
# #     conn = get_db_connection()
# #     cur = conn.cursor()
# #     cur.execute('SELECT * FROM locations;')
# #     locations = cur.fetchall()
# #     cur.close()
# #     conn.close()

# #     # Convert to a list of dictionaries
# #     locations_list = []
# #     for location in locations:
# #         locations_list.append({
# #             'id': location[0],
# #             'name': location[1],
# #             'latitude': float(location[2]),
# #             'longitude': float(location[3]),
# #             'description': location[4]
# #         })

# #     return jsonify(locations_list)

# # if __name__ == '__main__':
# #     app.run(debug=True)


# from flask import Flask, jsonify
# from flask_cors import CORS
# import psycopg2

# app = Flask(__name__)
# CORS(app)  # Enable CORS for all routes

# # Database connection function
# def get_db_connection():
#     conn = psycopg2.connect(
#         host='localhost',
#         database='mineLocation',
#         user='postgres',
#         password='1234'
#     )
#     return conn

# # Root endpoint
# @app.route('/', methods=['GET'])
# def index():
#     return "Welcome to the Locations API!"

# # API endpoint to fetch locations
# @app.route('/locations', methods=['GET'])
# def get_locations():
#     conn = get_db_connection()
#     cur = conn.cursor()
#     cur.execute('SELECT * FROM locations;')
#     locations = cur.fetchall()
#     cur.close()
#     conn.close()

#     # Convert to a list of dictionaries
#     locations_list = []
#     for location in locations:
#         locations_list.append({
#             'id': location[0],
#             'name': location[1],
#             'latitude': float(location[2]),
#             'longitude': float(location[3]),
#             'description': location[4],
#             'image': location[5],
#             'longDes': location[6],
#         })

#     print("Returning locations:", locations_list)  # Debugging output

#     return jsonify(locations_list)

# if __name__ == '__main__':
#     app.run(debug=True)

from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import bcrypt
from datetime import datetime, timedelta
import os
import psycopg2
from psycopg2.extras import DictCursor

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a3b1e2c4d5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2')
app.config['JWT_EXPIRATION_DELTA'] = timedelta(hours=1)

# Database configuration
DB_CONFIG = {
    'dbname': os.environ.get('DB_NAME', 'users'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'password': os.environ.get('DB_PASSWORD', '1234'),
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('DB_PORT', '5432')
}

def get_db_connection():
    """Create and return a database connection"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        raise

def generate_token(user_id):
    """Generate JWT token for authenticated user"""
    payload = {
        'sub': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + app.config['JWT_EXPIRATION_DELTA']
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Input validation
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Missing username or password"}), 400
    
    username = data['username']
    password = data['password']
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=DictCursor) as cur:
            # Query user from database
            cur.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = %s",
                (username,)
            )
            user = cur.fetchone()
            
            if not user:
                return jsonify({"message": "Invalid credentials"}), 401
            
            # Password verification
            try:
                password_valid = bcrypt.checkpw(
                    password.encode('utf-8'),
                    user['password_hash'].encode('utf-8')
                )
            except Exception as e:
                print(f"Password verification error: {e}")
                return jsonify({"message": "Invalid credentials"}), 401
            
            if not password_valid:
                return jsonify({"message": "Invalid credentials"}), 401
            
            # Generate JWT token
            token = generate_token(user['id'])
            
            return jsonify({
                "token": token,
                "user": {
                    "id": user['id'],
                    "username": user['username'],
                    "role": user['role']
                }
            }), 200
            
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return jsonify({"message": "Internal server error"}), 500
    finally:
        conn.close()

@app.route('/api/protected', methods=['GET'])
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"message": "Missing or invalid authorization header"}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # Verify user exists in database
        conn = get_db_connection()
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(
                "SELECT id, username FROM users WHERE id = %s",
                (payload['sub'],)
            )
            user = cur.fetchone()
            
            if not user:
                raise jwt.InvalidTokenError
            
            return jsonify({
                "message": f"Hello {user['username']}!",
                "user_id": user['id']
            }), 200
            
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return jsonify({"message": "Internal server error"}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)