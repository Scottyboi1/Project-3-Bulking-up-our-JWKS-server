import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import os
import uuid
from passlib.hash import argon2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
from http.server import BaseHTTPRequestHandler
from passlib.hash import argon2
import string
import secrets

def generate_secure_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    secure_password = ''.join(secrets.choice(characters) for _ in range(length))
    return secure_password

# Example usage:
password = generate_secure_password()
print("Generated Password:", password)
def get_encryption_key():
    key = os.environ.get("ENCRYPTION_KEY")

    if key is None:
        # If the key doesn't exist, generate a new one
        key = os.urandom(32)
        key_str = base64.urlsafe_b64encode(key).decode('utf-8')

        # Set the environment variable with the string representation of the key
        os.environ["ENCRYPTION_KEY"] = key_str

    # Convert the string representation back to bytes before returning
    return base64.urlsafe_b64decode(os.environ["ENCRYPTION_KEY"])

hostName = "localhost"
serverPort = 8080

# Creates the SQLite database file
database_file = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(database_file)

# Define the table schema for storing private keys
create_table_keys_sql = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

# Define the table schema for storing users
create_table_users_sql = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
"""

# Define the table schema for logging authentication requests
create_table_auth_logs_sql = """
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
"""

# Executes the SQL to create the tables
conn.execute(create_table_keys_sql)
conn.execute(create_table_users_sql)
conn.execute(create_table_auth_logs_sql)
conn.commit()

# Add a function to encrypt private keys
def encrypt_private_key(key, expiration_time):
    encryption_key = get_encryption_key()
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(b'\0'*16), backend=default_backend())
    cipher_text = cipher.encryptor().update(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    insert_sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    conn.execute(insert_sql, (cipher_text, int(expiration_time.timestamp())))
    conn.commit()


# Add a function to handle user registration
def register_user(username, email):
    generated_password = str(uuid.uuid4())
    hashed_password = argon2.hash(generated_password)

    # Store user details and hashed password in the users table
    insert_user_sql = "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)"
    conn.execute(insert_user_sql, (username, hashed_password, email))
    conn.commit()

    return generated_password

# Update the existing store_private_key function call
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
encrypt_private_key(private_key, expiration_time)

expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expiration_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
encrypt_private_key(expired_key, expiration_time)

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path == "/auth":
            self.log_auth_request()

            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }

            if 'expired' in parse_qs(parsed_path.query):
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            else:
                headers["kid"] = "goodKID"
                token_payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(encoded_jwt.encode('utf-8'))

        elif parsed_path.path == "/register":
            self.handle_registration()

        else:
            self.send_response(405)
            self.end_headers()
            return

    def log_auth_request(self):
        # Log authentication request
        request_ip = self.client_address[0]
        user_id = None  # Replace this with actual user ID if available
        log_sql = "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)"
        conn.execute(log_sql, (request_ip, user_id))
        conn.commit()

    def handle_registration(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data.decode('utf-8'))

            secure_password = generate_secure_password()
            hashed_password = argon2.hash(secure_password)

            # Use the register_user function to store user details
            generated_password = register_user(user_data['username'], user_data.get('email'))

            response_data = {"password": generated_password}
            self.send_response(201)  # Created
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

        except Exception as e:
            print(f"Error handling registration: {str(e)}")
            self.send_response(500)  # Internal Server Error
            self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            cursor = conn.execute("SELECT key, kid FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
            keys_data = cursor.fetchall()
            jwks_keys = []
            for key_data in keys_data:
                key_bytes, kid = key_data

                # Decrypt the key data
                encryption_key = get_encryption_key()
                cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(b'\0'*16), backend=default_backend())
                decrypted_key_bytes = cipher.decryptor().update(key_bytes)

                private_key = serialization.load_pem_private_key(decrypted_key_bytes, password=None)
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()
                jwks_key = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": kid,
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                }
                jwks_keys.append(jwks_key)

            jwks = {
                "keys": jwks_keys
            }

            # Send the JWKS response
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(jwks).encode('utf-8'))
            return

        self.send_response(405)
        self.end_headers()
        return

def close_database_connection():
    conn.close()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    close_database_connection()