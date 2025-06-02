from crypto_utils import encrypt_file, decrypt_file

def main():
    print("=== Cifrador/Descifrador de Archivos ===")
    print("1. Cifrar archivo")
    print("2. Descifrar archivo")
    choice = input("Seleccione una opción (1 o 2): ")

    if choice == '1':
        input_file = input("Ruta del archivo a cifrar: ")
        password = input("Contraseña: ")
        output_file = input("Ruta del archivo cifrado (.enc): ")
        encrypt_file(input_file, password, output_file)
        print(f"Archivo cifrado y guardado en: {output_file}")
    elif choice == '2':
        input_file = input("Ruta del archivo cifrado: ")
        password = input("Contraseña: ")
        output_file = input("Ruta para guardar el archivo descifrado: ")
        decrypt_file(input_file, password, output_file)
    else:
        print("Opción no válida")

if __name__ == "__main__":
    main()
