#**Informe del Proyecto: Cifrador/Descifrador de Archivos con AES**

## **Descripción General**

Este proyecto consiste en la creación de un programa en Python que permite *cifrar y descifrar archivos* utilizando el algoritmo *AES-256* en modo *CBC. La clave de cifrado se genera a partir de una contraseña, usando el algoritmo **PBKDF2-HMAC-SHA256* con un salt aleatorio para mejorar la seguridad. Además, se calcula un *hash SHA-256* del archivo original para verificar su integridad durante el proceso de descifrado.

---

## **Funcionamiento**

El programa tiene dos funcionalidades principales:

1. *Cifrado de archivo*
   - El usuario ingresa un archivo y una contraseña.
   - Se genera un salt aleatorio (16 bytes).
   - A partir de la contraseña y el salt, se deriva una clave de 256 bits usando PBKDF2.
   - Se genera un vector de inicialización (IV) de 16 bytes para AES-CBC.
   - Se calcula el hash SHA-256 del archivo original.
   - Se cifra el contenido usando AES-256-CBC con relleno PKCS7.
   - El archivo de salida contiene: salt + iv + hash + datos cifrados.

2. *Descifrado de archivo*
   - El usuario proporciona el archivo cifrado y la misma contraseña.
   - Se extraen salt, iv, hash y datos cifrados.
   - Se deriva nuevamente la clave usando PBKDF2.
   - Se descifran los datos con AES-256-CBC.
   - Se calcula el hash del archivo descifrado y se compara con el almacenado.
   - Si el hash coincide, se escribe el archivo descifrado. Si no, se alerta integridad comprometida.

---

## **Proceso de Desarrollo**

### **Elecciones Técnicas**

- Se usó la librería *cryptography* únicamente para implementar los algoritmos criptográficos (AES, PBKDF2, PKCS7), tal como lo permite el criterio de evaluación.
- Toda la lógica del proceso fue desarrollada manualmente: lectura y escritura de archivos, estructura binaria del archivo cifrado, verificación de integridad, y flujo interactivo.

### **Estructura del archivo cifrado**
#### $[$salt$ (16B)] + [$iv$ (16B)] + [$hash SHA-256$ (32B)] + [$datos cifrados$]$
---

## **Dificultades Encontradas**

- *Evitar el uso de funciones que cifren archivos automáticamente* fue un reto clave. Para cumplir la consigna, se evitó usar funciones como encrypt_file() de librerías de alto nivel.
- *Entender el manejo de padding* (relleno) fue necesario para poder cifrar bloques correctamente con AES.
- Hubo que *controlar bien la lectura y escritura en binario*, ya que los archivos cifrados no pueden tratarse como texto.
- Asegurar que *el mismo salt y iv no se repitan*, ya que rompería la seguridad del esquema AES-CBC.

---

## **Conclusiones**

- El uso de *cryptography* permitió aplicar correctamente estándares criptográficos reales como AES y PBKDF2, mientras se conservó la lógica del proyecto como un desarrollo propio.
- Se aprendió cómo se estructura un archivo cifrado de manera segura y cómo realizar una verificación de integridad basada en hash.
- La experiencia permitió entender mejor la diferencia entre *usar una herramienta* y *entender el proceso criptográfico* subyacente.
- Se recomienda usar esta implementación solo con fines educativos; en aplicaciones reales se deben reforzar aspectos como el manejo de errores y autenticación del mensaje (ej. HMAC).

---
## **Autores**

- Luis Pinillos
- Kevin Loachamin
- Santiago Belalcázar
- Daniel Montezuma
