import os
import shutil


def evaluar_contrasena(clave):
  """Evalúa la fortaleza de una contraseña de forma fácil y rápida."""
  longitud = len(clave)
  tiene_mayuscula = any(c.isupper() for c in clave)
  tiene_numero = any(c.isdigit() for c in clave)

  print("\n--- RESULTADO DE LA EVALUACIÓN ---")
  print(f"Longitud de la clave: {longitud} caracteres")

  if longitud >= 8 and tiene_mayuscula and tiene_numero:
    return (
        "🟢 NIVEL FUERTE: Tu contraseña es segura. Cumple con mayúsculas,"
        " números y buena longitud."
    )
  elif longitud >= 6:
    return (
        "🟡 NIVEL MEDIO: La contraseña es aceptable, pero te recomendamos"
        " agregar números y mayúsculas."
    )
  else:
    return (
        "🔴 NIVEL DÉBIL: Tu contraseña es muy vulnerable. Cámbiala por una más"
        " larga de inmediato."
    )


def hacer_copia_respaldo():
  """Simula o crea una copia de seguridad rápida comprimida en formato .ZIP."""
  print("\n--- MÓDULO DE COPIA DE SEGURIDAD (BACKUP) ---")
  carpeta = input(
      "Ingresa el nombre o ruta de la carpeta que deseas respaldar (o presiona"
      " ENTER para la actual): "
  ).strip()

  if not carpeta:
    carpeta = "."

  if os.path.exists(carpeta):
    try:
      # Crea un archivo ZIP con la copia
      nombre_zip = "Respaldo_Seguro_TIC"
      shutil.make_archive(nombre_zip, "zip", carpeta)
      print(
          "🟢 ¡Éxito! Copia de seguridad guardada correctamente como"
          f" '{nombre_zip}.zip'."
      )
    except Exception as e:
      print(f"🔴 Ocurrió un error al crear la copia: {e}")
  else:
    print("⚠️ La carpeta o ruta especificada no existe.")


def menu_principal():
  """Menú interactivo fácil de usar."""
  while True:
    print("\n==========================================")
    print("   SISTEMA DE SEGURIDAD INFORMÁTICA TIC   ")
    print("==========================================")
    print("1. Evaluar fortaleza de una contraseña")
    print("2. Crear copia de seguridad (Backup)")
    print("3. Salir")

    opcion = input("\nElige una opción (1, 2 o 3): ").strip()

    if opcion == "1":
      clave = input("Ingresa la contraseña a probar: ")
      resultado = evaluar_contrasena(clave)
      print(resultado)
    elif opcion == "2":
      hacer_copia_respaldo()
    elif opcion == "3":
      print("\n¡Gracias por usar SecureCheck TIC! Hasta luego.")
      break
    else:
      print("⚠️ Opción no válida. Por favor escribe 1, 2 o 3.")


if __name__ == "__main__":
  menu_principal()
