#Env: 3550p2
# Run the gradebot for project 1: go run main.go project1 -p 8080
# Run the gradebot for project 2: go run main.go project2 -p 8080 -databasefile <database_file_path> -codedir <code_directory_path>

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

os.environ["NOT_MY_KEY"] = "1"

# Set the encryption key from the environment variable
encryption_key = os.environ.get('NOT_MY_KEY')

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

# Set the encryption key from the environment variable
encryption_key = os.environ.get('NOT_MY_KEY')

if encryption_key is None:
    raise ValueError("Environment variable NOT_MY_KEY is not set.")

# Ensure a valid key size for AES (e.g., 16, 24, or 32 bytes)
valid_key_size = 32  # You can adjust this value based on your security requirements

# Pad or hash the key to achieve the desired length
encryption_key = (encryption_key * (valid_key_size // len(encryption_key)))[:valid_key_size]

# Create/open SQLite DB file at start
connection = sqlite3.connect('totally_not_my_privateKeys.db')

cursor = connection.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )
''')

# Server code

hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize private keys to PEM format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# PKCS1 serialization
pempkcs1 = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pempkcs1 = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Encrypt private keys using AES with the provided key
cipher = Cipher(algorithms.AES(encryption_key.encode('utf-8')), modes.CFB8(os.urandom(16)), backend=default_backend())
pem_encrypted = cipher.encryptor().update(pem)
expired_pem_encrypted = cipher.encryptor().update(expired_pem)

# Generate/store at least one key that expires now and one key that expires in 1 hour
cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (1, expired_pem_encrypted, datetime.datetime.utcnow()))
cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (2, pem_encrypted, datetime.datetime.utcnow() + datetime.timedelta(hours=1)))

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
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
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            cursor.execute("SELECT key FROM keys WHERE kid = 2")
            row = cursor.fetchone()
            selected_pem = row[0]  # Assuming the key is in the first column (index 0)
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                cursor.execute("SELECT key FROM keys WHERE kid = 1")
                row = cursor.fetchone()
                selected_pem = row[0]  # Assuming the key is in the first column (index 0)
            
            # Deserialize selected_pem
            decoded_selected_pem = serialization.load_pem_private_key(selected_pem, password=None, backend=default_backend())

            encoded_jwt = jwt.encode(token_payload, decoded_selected_pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
