#Env: 3550p2
# Run the gradebot for project 1: go run main.go project1 -p 8080
# Run the gradebot for project 2: go run main.go project2 -p 8080 -databasefile <database_file_path> -codedir <code_directory_path>

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
from argon2 import PasswordHasher as ph
from threading import Lock
import time

# Define a token bucket for rate limiting
class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill_time = time.time()
        self.refill_rate = refill_rate
        self.lock = Lock()

    def _refill(self):
        now = time.time()
        elapsed_time = now - self.last_refill_time
        tokens_to_add = elapsed_time * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill_time = now

    def consume(self, tokens):
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

# Create a token bucket with a capacity of 10 and a refill rate of 1 token per second
rate_limiter = TokenBucket(capacity=10, refill_rate=1)

# Create/open SQLite DB file at start
connection = sqlite3.connect('totally_not_my_privateKeys.db', detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)

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
        last_login TIMESTAMP DEFAULT NULL    
)
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,  
        FOREIGN KEY(user_id) REFERENCES users(id)
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

# Generate/store at least one key that expires now and one key that expires in 1 hour
cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (1, expired_pempkcs1, int(datetime.datetime.timestamp(datetime.datetime.now(datetime.timezone.utc)))))
cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (2, pempkcs1, int(datetime.datetime.timestamp(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)))))

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
            # Rate limit requests to 10 requests per second
            if not rate_limiter.consume(1):
                self.send_response(429)  # Too Many Requests
                self.end_headers()
                return
            
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
        elif parsed_path.path == "/register":
            # Parse the request body to get the username and email
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))
            username = request_data.get('username')
            email = request_data.get('email', None)  # Get the email or set to None if not provided

            # Check if the username already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                self.send_response(400)  # Bad Request
                self.end_headers()
                return

            # Generate a random UUID as the password
            password = str(uuid.uuid4())

            # Hash the password using argon2
            ph_instance = ph()
            password_hash = ph_instance.hash(password)

            # Insert the new user into the database, handling the case when email is not provided
            if email is not None:
                cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
            else:
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))

            # Retrieve the newly inserted user, coalescing NULL values in last_login
            cursor.execute("SELECT id, username, password_hash, email, date_registered, last_login FROM users WHERE username = ?", (username,))

            new_user = cursor.fetchone()

            connection.commit()

            # Return the password and last_login to the client
            last_login = new_user[5] if new_user[5] is not None else None
            response_data = {"password": password, "last_login": last_login}
            self.send_response(201)  # Created
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response_data), "utf-8"))

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
