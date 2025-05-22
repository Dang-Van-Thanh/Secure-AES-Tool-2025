from flask import Flask, render_template, request, send_file, redirect, flash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def aes_encrypt(file_path, key, key_size, output_path):
    # Validate key length based on selected key size
    required_key_length = key_size // 8
    if len(key.encode('utf-8')) != required_key_length:
        raise ValueError(f"For AES-{key_size}, key must be {required_key_length} bytes long")
    
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    iv = cipher.iv  # Get the initialization vector
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    
    # Prepend the IV to the encrypted data (needed for decryption)
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted_data)
        print("Saving encrypted file to:", output_path)

def aes_decrypt(file_path, key, key_size, output_path):
    # Validate key length based on selected key size
    required_key_length = key_size // 8
    if len(key.encode('utf-8')) != required_key_length:
        raise ValueError(f"For AES-{key_size}, key must be {required_key_length} bytes long")
    
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Extract the IV from the beginning of the file
    iv = encrypted_data[:AES.block_size]
    encrypted_data = encrypted_data[AES.block_size:]
    
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_data = unpad(decrypted_data, AES.block_size)
    except ValueError as e:
        raise ValueError("Invalid key, corrupted file, or incorrect key size.") from e
    
    with open(output_path, 'wb') as f:
        f.write(unpadded_data)
        print("Saving decrypted file to:", output_path)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files.get('file')
        key = request.form.get('key')
        operation = request.form.get('operation')
        key_size = int(request.form.get('key_size', 256))  # Default to 256-bit
        
        # Validate inputs
        if not file:
            flash('Please upload a file.')
            return redirect(request.url)
            
        if not key:
            flash('Please enter an encryption key.')
            return redirect(request.url)
            
        required_key_length = key_size // 8
        if len(key.encode('utf-8')) != required_key_length:
            flash(f'For AES-{key_size}, key must be exactly {required_key_length} characters (bytes) long.')
            return redirect(request.url)

        input_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(input_path)

        output_filename = f"{operation}ed_{file.filename}"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        try:
            if operation == 'encrypt':
                aes_encrypt(input_path, key, key_size, output_path)
            elif operation == 'decrypt':
                aes_decrypt(input_path, key, key_size, output_path)
            else:
                flash('Invalid operation selected.')
                return redirect(request.url)
        except Exception as e:
            flash(str(e))
            return redirect(request.url)

        return send_file(output_path, as_attachment=True, download_name=output_filename)

    return render_template('index.html')
    
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)