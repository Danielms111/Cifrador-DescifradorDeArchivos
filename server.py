"""
Servidor web Flask para el cifrador/descifrador de archivos.

Este módulo implementa una API web RESTful que proporciona una interfaz
web moderna para las funciones de cifrado y descifrado de archivos.

Características:
- Servidor web Flask con interfaz HTML moderna
- API REST para cifrado y descifrado de archivos
- Validación de entrada y manejo robusto de errores
- Límite de tamaño de archivo (100MB)
- Descarga automática de archivos procesados

Endpoints:
- GET /: Sirve la interfaz web HTML
- POST /encrypt: Cifra un archivo subido
- POST /decrypt: Descifra un archivo subido

Uso:
    python server.py
    
Luego acceder a: http://localhost:5000

Requisitos:
- Flask
- crypto_utils (módulo local)
- index.html (archivo de interfaz)

"""

from flask import Flask, request, send_file, jsonify, render_template_string
import os
import tempfile
import traceback
from crypto_utils import encrypt_file, decrypt_file, manual_encrypt_file, manual_decrypt_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

@app.route('/')
def index():
    """
    Endpoint principal que sirve la interfaz web HTML.
    
    Returns:
        str: Contenido del archivo index.html con la interfaz de usuario
        
    Raises:
        FileNotFoundError: Si el archivo index.html no existe
    """
    with open('index.html', 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """
    Endpoint para cifrar archivos subidos por el usuario.
    
    Acepta un archivo y una contraseña mediante POST multipart/form-data,
    cifra el archivo usando AES-256 y devuelve el archivo cifrado para descarga.
    
    Form Data esperada:
        file: Archivo a cifrar (multipart/form-data)
        password: Contraseña para el cifrado (string)
    
    Returns:
        Response: Archivo cifrado para descarga (.enc) o mensaje de error
        
    HTTP Status Codes:
        200: Éxito - archivo cifrado devuelto
        400: Error de entrada (archivo no seleccionado, sin contraseña)
        500: Error interno del servidor
        
    Proceso:
        1. Valida que se haya subido un archivo y proporcionado contraseña
        2. Guarda el archivo en un directorio temporal
        3. Cifra el archivo usando crypto_utils.encrypt_file()
        4. Devuelve el archivo cifrado para descarga automática
        5. Limpia archivos temporales
    """
    try:
        if 'file' not in request.files:
            return 'No se seleccionó ningún archivo', 400
        
        file = request.files['file']
        password = request.form.get('password')

        if file.filename == '':
            return 'No se seleccionó ningún archivo', 400
        
        if not password:
            return 'No se proporcionó contraseña', 400

        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            file.save(temp_input.name)
            temp_input_path = temp_input.name
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.enc') as temp_output:
            temp_output_path = temp_output.name
        
        try:
            encrypt_file(temp_input_path, password, temp_output_path)
            
            return send_file(
                temp_output_path,
                as_attachment=True,
                download_name=secure_filename(file.filename) + '.enc',
                mimetype='application/octet-stream'
            )
        
        finally:
            try:
                os.unlink(temp_input_path)
                if os.path.exists(temp_output_path):
                    pass
            except:
                pass
    
    except Exception as e:
        print(f"Error en cifrado: {str(e)}")
        print(traceback.format_exc())
        return f'Error al cifrar el archivo: {str(e)}', 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """
    Endpoint para descifrar archivos cifrados subidos por el usuario.
    
    Acepta un archivo cifrado (.enc) y una contraseña mediante POST multipart/form-data,
    descifra el archivo usando AES-256 con verificación de integridad y devuelve 
    el archivo original para descarga.
    
    Form Data esperada:
        file: Archivo cifrado a descifrar (.enc) (multipart/form-data)
        password: Contraseña utilizada en el cifrado (string)
    
    Returns:
        Response: Archivo descifrado para descarga o mensaje de error específico
        
    HTTP Status Codes:
        200: Éxito - archivo descifrado devuelto
        400: Error de entrada (archivo no seleccionado, sin contraseña)
        401: Contraseña incorrecta o archivo corrupto
        500: Error interno del servidor
        
    Proceso:
        1. Valida que se haya subido un archivo cifrado y proporcionado contraseña
        2. Guarda el archivo en un directorio temporal
        3. Descifra el archivo usando crypto_utils.decrypt_file() con validaciones
        4. Si la verificación de integridad pasa, devuelve el archivo original
        5. Si falla, devuelve error específico (contraseña incorrecta/archivo corrupto)
        6. Limpia archivos temporales
        
    Seguridad:
        - Validación de contraseña mediante verificación de integridad
        - Detección de archivos corruptos o modificados
        - Limpieza automática de archivos temporales en caso de error
    """
    try:
        if 'file' not in request.files:
            return 'No se seleccionó ningún archivo', 400
        
        file = request.files['file']
        password = request.form.get('password')
        
        if file.filename == '':
            return 'No se seleccionó ningún archivo', 400
        
        if not password:
            return 'No se proporcionó contraseña', 400
            
        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            file.save(temp_input.name)
            temp_input_path = temp_input.name
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_output:
            temp_output_path = temp_output.name
        
        try:
            decrypt_file(temp_input_path, password, temp_output_path)
            
            original_name = secure_filename(file.filename)
            if original_name.endswith('.enc'):
                decrypted_name = original_name[:-4]
            else:
                decrypted_name = 'descifrado_' + original_name
            
            return send_file(
                temp_output_path,
                as_attachment=True,
                download_name=decrypted_name,
                mimetype='application/octet-stream'
            )
        
        finally:
            try:
                os.unlink(temp_input_path)
                if os.path.exists(temp_output_path):
                    pass
            except:
                pass
    
    except ValueError as e:
        error_msg = str(e)
        print(f"Error de validación en descifrado: {error_msg}")
        if "Contraseña incorrecta" in error_msg:
            return 'Contraseña incorrecta o archivo corrupto', 401
        else:
            return f'Error de validación: {error_msg}', 400
    
    except Exception as e:
        print(f"Error inesperado en descifrado: {str(e)}")
        print(traceback.format_exc())
        return f'Error interno del servidor: {str(e)}', 500

@app.route('/manual_encrypt', methods=['POST'])
def manual_encrypt():
    """
    Endpoint para cifrado manual de archivos subidos por el usuario.
    
    Acepta un archivo y una contraseña mediante POST multipart/form-data,
    cifra el archivo usando un cifrado manual (XOR) y devuelve el archivo cifrado para descarga.
    
    Form Data esperada:
        file: Archivo a cifrar (multipart/form-data)
        password: Contraseña para el cifrado (string)
    
    Returns:
        Response: Archivo cifrado para descarga (.xor) o mensaje de error
        
    HTTP Status Codes:
        200: Éxito - archivo cifrado devuelto
        400: Error de entrada (archivo no seleccionado, sin contraseña)
        500: Error interno del servidor
        
    Proceso:
        1. Valida que se haya subido un archivo y proporcionado contraseña
        2. Guarda el archivo en un directorio temporal
        3. Cifra el archivo usando crypto_utils.manual_encrypt_file()
        4. Devuelve el archivo cifrado para descarga automática
        5. Limpia archivos temporales
    """
    try:
        if 'file' not in request.files:
            return 'No se seleccionó ningún archivo', 400
        
        file = request.files['file']
        password = request.form.get('password')

        if file.filename == '':
            return 'No se seleccionó ningún archivo', 400
        
        if not password:
            return 'No se proporcionó contraseña', 400

        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            file.save(temp_input.name)
            temp_input_path = temp_input.name
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xor') as temp_output:
            temp_output_path = temp_output.name
        
        try:
            manual_encrypt_file(temp_input_path, password, temp_output_path)
            
            return send_file(
                temp_output_path,
                as_attachment=True,
                download_name=secure_filename(file.filename) + '.xor',
                mimetype='application/octet-stream'
            )
        
        finally:
            try:
                os.unlink(temp_input_path)
                if os.path.exists(temp_output_path):
                    pass
            except:
                pass
    
    except Exception as e:
        print(f"Error en cifrado manual: {str(e)}")
        print(traceback.format_exc())
        return f'Error al cifrar manualmente el archivo: {str(e)}', 500

@app.route('/manual_decrypt', methods=['POST'])
def manual_decrypt():
    """
    Endpoint para descifrar archivos cifrados manualmente subidos por el usuario.
    
    Acepta un archivo cifrado (.xor) y una contraseña mediante POST multipart/form-data,
    descifra el archivo usando el cifrado manual (XOR) y devuelve 
    el archivo original para descarga.
    
    Form Data esperada:
        file: Archivo cifrado a descifrar (.xor) (multipart/form-data)
        password: Contraseña utilizada en el cifrado (string)
    
    Returns:
        Response: Archivo descifrado para descarga o mensaje de error específico
        
    HTTP Status Codes:
        200: Éxito - archivo descifrado devuelto
        400: Error de entrada (archivo no seleccionado, sin contraseña)
        401: Contraseña incorrecta o archivo corrupto
        500: Error interno del servidor
        
    Proceso:
        1. Valida que se haya subido un archivo cifrado y proporcionado contraseña
        2. Guarda el archivo en un directorio temporal
        3. Descifra el archivo usando crypto_utils.manual_decrypt_file() con validaciones
        4. Si la verificación de integridad pasa, devuelve el archivo original
        5. Si falla, devuelve error específico (contraseña incorrecta/archivo corrupto)
        6. Limpia archivos temporales
        
    Seguridad:
        - Validación de contraseña mediante verificación de integridad
        - Detección de archivos corruptos o modificados
        - Limpieza automática de archivos temporales en caso de error
    """
    try:
        if 'file' not in request.files:
            return 'No se seleccionó ningún archivo', 400
        
        file = request.files['file']
        password = request.form.get('password')
        
        if file.filename == '':
            return 'No se seleccionó ningún archivo', 400
        
        if not password:
            return 'No se proporcionó contraseña', 400
            
        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            file.save(temp_input.name)
            temp_input_path = temp_input.name
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_output:
            temp_output_path = temp_output.name
        
        try:
            manual_decrypt_file(temp_input_path, password, temp_output_path)
            
            original_name = secure_filename(file.filename)
            if original_name.endswith('.xor'):
                decrypted_name = original_name[:-4]
            else:
                decrypted_name = 'descifrado_' + original_name
            
            return send_file(
                temp_output_path,
                as_attachment=True,
                download_name=decrypted_name,
                mimetype='application/octet-stream'
            )
        
        finally:
            try:
                os.unlink(temp_input_path)
                if os.path.exists(temp_output_path):
                    pass
            except:
                pass
    
    except ValueError as e:
        error_msg = str(e)
        print(f"Error de validación en descifrado manual: {error_msg}")
        return f'Contraseña incorrecta o archivo corrupto', 401
    
    except Exception as e:
        print(f"Error inesperado en descifrado manual: {str(e)}")
        print(traceback.format_exc())
        return f'Error interno del servidor: {str(e)}', 500

if __name__ == '__main__':
    print("=== Servidor Web - Cifrador/Descifrador de Archivos ===")
    print("Iniciando servidor...")
    print("Accede a: http://localhost:5000")
    print("Presiona Ctrl+C para detener el servidor")
    print("-" * 50)
    
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    except Exception as e:
        print(f"\nError al iniciar el servidor: {str(e)}")
        print("Verifica que el puerto 5000 esté disponible.")
