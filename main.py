import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

hostName = "localhost"
serverPort = 8080

#Creates the SQLite database file
database_file = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(database_file)

#Define the table schema for storing private keys
create_table_sql = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

#Executes the SQL to create the table
conn.execute(create_table_sql)
conn.commit()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def store_private_key(key, expiration_time):
    """Serialize and store private keys in the database"""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    #Insert the serialized key into database
    insert_sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    conn.execute(insert_sql, (pem, expiration_time))
    conn.commit()

#Gets RSA Key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
store_private_key(private_key, expiration_time)

expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expiration_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
store_private_key(expired_key, expiration_time)

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
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            cursor = conn.execute("SELECT key FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1", (int(datetime.datetime.utcnow().timestamp()),))
            row = cursor.fetchone()
            if row is None:
                self.send_response(404)
                self.end_headers()
                return
            key_bytes = row[0]
            private_key = serialization.load_pem_private_key(key_bytes, password=None)
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(encoded_jwt.encode('utf-8'))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            cursor = conn.execute("SELECT key, kid FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
            keys_data = cursor.fetchall()
            jwks_keys = []
            for key_data in keys_data:
                key_bytes, kid = key_data
                private_key = serialization.load_pem_private_key(key_bytes, password=None)
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
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(jwks).encode('utf-8'))
            return

        self.send_response(405)
        self.end_headers()
        return

#Close the database connection when the server is shut down
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
