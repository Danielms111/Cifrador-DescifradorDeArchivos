# 🔐 Cifrador/Descifrador de Archivos

Una aplicación segura para cifrar y descifrar archivos usando cifrado AES-256 con autenticación de integridad.

## 🌟 Características

- **Cifrado AES-256**: Usa el estándar de cifrado avanzado con claves de 256 bits
- **Verificación de integridad**: Incluye hash SHA-256 para verificar la integridad del archivo
- **Interfaz web moderna**: Frontend HTML con diseño responsivo
- **Interfaz de línea de comandos**: Para uso desde terminal
- **Seguridad robusta**: Derivación de claves PBKDF2 con 100,000 iteraciones

## 🚀 Uso Rápido

### Opción 1: Interfaz Web (Recomendado)

1. **Ejecuta el archivo `run_server.bat`** (doble clic)
2. **Abre tu navegador** y ve a: `http://localhost:5000`
3. **Selecciona la pestaña** "Cifrar" o "Descifrar"
4. **Sube tu archivo** y escribe la contraseña
5. **Haz clic en el botón** correspondiente
6. **El archivo procesado se descargará automáticamente**

### Opción 2: Línea de Comandos

```bash
# Instalar dependencias
pip install -r requirements.txt

# Ejecutar la aplicación
python main.py
```

## 📋 Requisitos

- Python 3.7 o superior
- Bibliotecas de Python (se instalan automáticamente):
  - `cryptography`
  - `flask`

## 🔧 Instalación Manual

```bash
# Clonar o descargar el proyecto
cd Cifrador-DescifradorDeArchivos

# Instalar dependencias
pip install -r requirements.txt

# Para interfaz web
python server.py

# Para interfaz de comandos
python main.py
```

## 🛡️ Seguridad

- **Cifrado AES-256-CBC**: Uno de los algoritmos de cifrado más seguros
- **Salt aleatorio**: Cada cifrado usa un salt único de 16 bytes
- **IV aleatorio**: Vector de inicialización único para cada operación
- **PBKDF2**: Derivación de claves con 100,000 iteraciones para resistir ataques de fuerza bruta
- **Verificación SHA-256**: Hash del archivo original para verificar integridad

## 📁 Estructura del Proyecto

```
Cifrador-DescifradorDeArchivos/
├── crypto_utils.py      # Lógica de cifrado/descifrado
├── main.py             # Interfaz de línea de comandos
├── server.py           # Servidor web Flask
├── index.html          # Frontend web
├── run_server.bat      # Script para ejecutar fácilmente
├── requirements.txt    # Dependencias de Python
└── README.md          # Este archivo
```

## 🎨 Capturas de Pantalla

La interfaz web incluye:
- ✅ Diseño moderno y responsivo
- ✅ Pestañas para cifrar/descifrar
- ✅ Indicador de progreso
- ✅ Mensajes de éxito/error
- ✅ Información del archivo seleccionado
- ✅ Descarga automática de archivos procesados

## ⚠️ Importante

- **Guarda tu contraseña de forma segura**: Sin ella no podrás descifrar tus archivos
- **Los archivos cifrados tienen extensión .enc**: Mantén estos archivos seguros
- **Usa contraseñas fuertes**: Combina letras, números y símbolos
- **Haz copias de seguridad**: Tanto del archivo original como del cifrado

## 🐛 Solución de Problemas

### Error: "Python no encontrado"
- Instala Python desde [python.org](https://python.org)
- Asegúrate de marcar "Add Python to PATH" durante la instalación

### Error: "pip no encontrado"
- Reinstala Python con la opción "Add Python to PATH"
- O usa: `python -m ensurepip --upgrade`

### Error al instalar dependencias
- Ejecuta: `pip install --upgrade pip`
- Luego: `pip install -r requirements.txt`

### El servidor no inicia
- Verifica que el puerto 5000 no esté en uso
- Cierra otros programas que puedan usar ese puerto

## 📞 Soporte

Si encuentras algún problema:
1. Verifica que Python esté correctamente instalado
2. Asegúrate de que todas las dependencias estén instaladas
3. Revisa que no haya otros programas usando el puerto 5000

---

**¡Mantén tus archivos seguros! 🔒**