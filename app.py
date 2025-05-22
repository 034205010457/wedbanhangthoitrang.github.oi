from flask import Flask, request, render_template, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def aes_encrypt(data, key):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # prepend IV

def aes_decrypt(data, key):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        operation = request.form["operation"]
        key_input = request.form["key"].encode()

        if len(key_input) not in [16, 24, 32]:
            return "⚠️ Khóa phải có độ dài 16, 24 hoặc 32 byte!"

        file = request.files["file"]
        file_data = file.read()

        try:
            if operation == "encrypt":
                result = aes_encrypt(file_data, key_input)
                filename = "encrypted_" + file.filename
            else:
                result = aes_decrypt(file_data, key_input)
                filename = "decrypted_" + file.filename
        except Exception as e:
            return f"Lỗi khi xử lý file: {str(e)}"

        path = os.path.join(UPLOAD_FOLDER, filename)
        with open(path, "wb") as f:
            f.write(result)
        return send_file(path, as_attachment=True)

    return render_template("index.html")
