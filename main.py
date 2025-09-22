import sys
import os

# Incluye el dir /backend por si se ejecuta desde distintos lugares
sys.path.append(os.path.join(os.path.dirname(__file__), "backend"))

from backend.add_user import flujo_agregar_usuario
from backend.login import login_usuario
from backend.manage_user import menu_gestion

def seleccionar_idioma():
    print("Selecciona idioma / Select language:")
    print("1. Español (es)")
    print("2. English (en)")
    while True:
        idioma = input("Opción/Option: ")
        if idioma.strip() == "1":
            return "es"
        elif idioma.strip() == "2":
            return "en"
        else:
            print("Opción/Option inválida. Intenta de nuevo.")

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def main_menu():
    global LANG
    LANG = seleccionar_idioma()
    # Esto permite que todos los submódulos reciban el idioma (por si usan os.environ)
    os.environ["LANGUAGE"] = LANG + "_MX" if LANG == "es" else LANG + "_US"
    while True:
        clear()
        if LANG == "es":
            print("*** Sistema SGI - Menú Principal ***")
            print("1 - Iniciar sesión")
            print("2 - Añadir usuario")
            print("3 - Gestionar usuarios")
            print("4 - Salir")
        else:
            print("*** SGI System - Main Menu ***")
            print("1 - Login")
            print("2 - Add user")
            print("3 - Manage users")
            print("4 - Exit")
        op = input("> ").strip()
        if op == "1":
            login_usuario(LANG)
        elif op == "2":
            flujo_agregar_usuario(LANG)
        elif op == "3":
            menu_gestion(LANG)
        elif op == "4":
            clear()
            print("¡Hasta luego!" if LANG == "es" else "Goodbye!")
            break
        else:
            print("Opción inválida." if LANG == "es" else "Invalid option.")
            input("Presiona Enter..." if LANG == "es" else "Press Enter...")

if __name__ == "__main__":
    main_menu()
