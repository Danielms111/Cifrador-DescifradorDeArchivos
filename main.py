"""
Interfaz de línea de comandos para el cifrador/descifrador de archivos.

Este módulo proporciona una interfaz de usuario simple para interactuar con
las funciones de cifrado y descifrado desde la línea de comandos.

Características:
- Menú interactivo para seleccionar operación (cifrar/descifrar)
- Manejo robusto de errores con mensajes informativos
- Validación de entrada del usuario
- Integración completa con las funciones criptográficas

Uso:
    python main.py

El programa solicitará:
1. Selección de operación (1=cifrar, 2=descifrar)
2. Ruta del archivo de entrada
3. Contraseña
4. Ruta del archivo de salida

"""

from crypto_utils import encrypt_file, decrypt_file

def main():
    """
    Función principal que maneja la interfaz de línea de comandos.
    
    Presenta un menú al usuario para seleccionar entre cifrar o descifrar archivos,
    solicita los parámetros necesarios y ejecuta la operación correspondiente
    con manejo de errores apropiado.
    
    Flujo del programa:
    1. Muestra el menú principal
    2. Solicita la selección del usuario
    3. Según la opción, solicita los parámetros necesarios
    4. Ejecuta la operación de cifrado/descifrado
    5. Maneja y muestra errores de forma amigable
    
    Opciones disponibles:
    - Opción 1: Cifrar un archivo
    - Opción 2: Descifrar un archivo
    - Cualquier otra entrada: Mensaje de error
    """
    print("=== Cifrador/Descifrador de Archivos ===")
    print("1. Cifrar archivo")
    print("2. Descifrar archivo")
    choice = input("Seleccione una opción (1 o 2): ")

    if choice == '1':
        print("\n--- Cifrado de Archivo ---")
        input_file = input("Ruta del archivo a cifrar: ")
        password = input("Contraseña: ")
        output_file = input("Ruta del archivo cifrado (.enc): ")
        
        try:
            encrypt_file(input_file, password, output_file)
            print(f"Archivo cifrado exitosamente y guardado en: {output_file}")
        except FileNotFoundError:
            print("Error: El archivo especificado no existe.")
        except PermissionError:
            print("Error: No tienes permisos para acceder a los archivos especificados.")
        except Exception as e:
            print(f"Error al cifrar el archivo: {str(e)}")
            
    elif choice == '2':
        print("\n--- Descifrado de Archivo ---")
        input_file = input("Ruta del archivo cifrado: ")
        password = input("Contraseña: ")
        output_file = input("Ruta para guardar el archivo descifrado: ")
        
        try:
            decrypt_file(input_file, password, output_file)
            print(f"Archivo descifrado exitosamente y guardado en: {output_file}")
        except ValueError as e:
            if "Contraseña incorrecta" in str(e):
                print("Contraseña incorrecta. Verifica tu contraseña e intenta nuevamente.")
            else:
                print(f"Error de validación: {str(e)}")
        except FileNotFoundError:
            print("Error: El archivo cifrado especificado no existe.")
        except PermissionError:
            print("Error: No tienes permisos para acceder a los archivos especificados.")
        except Exception as e:
            print(f"Error inesperado: {str(e)}")
    else:
        print("Opción no válida. Por favor selecciona 1 o 2.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nPrograma interrumpido por el usuario. ¡Hasta luego!")
    except Exception as e:
        print(f"\nError inesperado en el programa: {str(e)}")
        print("Por favor reporta este error si persiste.")
