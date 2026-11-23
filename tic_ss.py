
from datetime import date

# SISTEMA DE CONTROL DE INCIDENTES DE SEGURIDAD INFORMATICA

incidentes = []

tipos_incidente = [
    "Phishing",
    "Malware",
    "Acceso no autorizado",
    "Perdida de informacion",
    "Software desactualizado"
]

gravedades = ["Bajo", "Medio", "Alto"]
estados = ["Pendiente", "En proceso", "Solucionado"]


# BUSCAR INCIDENTE
def buscar_incidente(identificador):
    for incidente in incidentes:
        if incidente["id"] == identificador:
            return incidente
    return None


# GENERAR IDENTIFICADOR
def generar_id():
    numero = len(incidentes) + 1
    return "INC-" + str(numero).zfill(3)


# REGISTRAR INCIDENTE
def registrar_incidente():

    print("\nREGISTRAR INCIDENTE")

    descripcion = input("Descripcion del incidente: ").strip()

    if not descripcion:
        print("La descripcion no puede estar vacia.")
        return

    print("\nTIPOS DE INCIDENTE")
    for i, tipo in enumerate(tipos_incidente, 1):
        print(i, "-", tipo)

    try:
        opcion_tipo = int(input("Seleccione el tipo: "))
        if opcion_tipo < 1 or opcion_tipo > len(tipos_incidente):
            print("Tipo de incidente no valido.")
            return
    except ValueError:
        print("Ingrese una opcion numerica.")
        return

    print("\nNIVEL DE GRAVEDAD")
    for i, gravedad in enumerate(gravedades, 1):
        print(i, "-", gravedad)

    try:
        opcion_gravedad = int(input("Seleccione la gravedad: "))
        if opcion_gravedad < 1 or opcion_gravedad > 3:
            print("Nivel de gravedad no valido.")
            return
    except ValueError:
        print("Ingrese una opcion numerica.")
        return

    incidente = {
        "id": generar_id(),
        "tipo": tipos_incidente[opcion_tipo - 1],
        "descripcion": descripcion,
        "gravedad": gravedades[opcion_gravedad - 1],
        "fecha": date.today().strftime("%d/%m/%Y"),
        "estado": "Pendiente"
    }

    incidentes.append(incidente)

    print("\nIncidente registrado correctamente.")
    print("Identificador:", incidente["id"])


# CONSULTAR INCIDENTES
def consultar_incidentes():

    print("\nLISTA DE INCIDENTES REGISTRADOS")

    if not incidentes:
        print("No existen incidentes registrados.")
        return

    for incidente in incidentes:
        print("\nID:", incidente["id"])
        print("Tipo:", incidente["tipo"])
        print("Descripcion:", incidente["descripcion"])
        print("Gravedad:", incidente["gravedad"])
        print("Fecha:", incidente["fecha"])
        print("Estado:", incidente["estado"])
        print("-" * 40)


# ACTUALIZAR ESTADO
def actualizar_estado():

    print("\nACTUALIZAR ESTADO DE INCIDENTE")

    identificador = input("Ingrese el ID del incidente: ").strip().upper()

    incidente = buscar_incidente(identificador)

    if incidente is None:
        print("El incidente indicado no existe.")
        return

    print("\nEstado actual:", incidente["estado"])
    print("\nESTADOS DISPONIBLES")

    for i, estado in enumerate(estados, 1):
        print(i, "-", estado)

    try:
        opcion = int(input("Seleccione el nuevo estado: "))

        if opcion < 1 or opcion > len(estados):
            print("Opcion no valida.")
            return

    except ValueError:
        print("Ingrese una opcion numerica.")
        return

    incidente["estado"] = estados[opcion - 1]

    print("Estado actualizado correctamente.")
    print("Nuevo estado:", incidente["estado"])


# GENERAR REPORTE
def generar_reporte():

    print("\nREPORTE GENERAL DE INCIDENTES")

    if not incidentes:
        print("No existen registros para generar el reporte.")
        return

    print("\nTOTAL DE INCIDENTES:", len(incidentes))

    print("\nINCIDENTES POR TIPO")

    for tipo in tipos_incidente:
        cantidad = sum(
            1 for i in incidentes if i["tipo"] == tipo
        )
        print(tipo + ":", cantidad)

    print("\nINCIDENTES POR GRAVEDAD")

    for gravedad in gravedades:
        cantidad = sum(
            1 for i in incidentes if i["gravedad"] == gravedad
        )
        print(gravedad + ":", cantidad)

    print("\nINCIDENTES POR ESTADO")

    for estado in estados:
        cantidad = sum(
            1 for i in incidentes if i["estado"] == estado
        )
        print(estado + ":", cantidad)


# CARGAR ESCENARIO DE PRUEBA
def cargar_escenario_prueba():

    global incidentes

    if incidentes:
        print("El escenario solo puede cargarse cuando no hay registros.")
        return

    datos_prueba = [
        ("Phishing", "Recepcion de correo sospechoso",
         "Alto", "Pendiente"),

        ("Malware", "Deteccion de archivo malicioso",
         "Alto", "En proceso"),

        ("Acceso no autorizado", "Intento de acceso sin permiso",
         "Alto", "Pendiente"),

        ("Perdida de informacion", "Eliminacion accidental de archivos",
         "Medio", "Solucionado"),

        ("Software desactualizado", "Sistema sin actualizaciones recientes",
         "Bajo", "Solucionado")
    ]

    for tipo, descripcion, gravedad, estado in datos_prueba:

        incidente = {
            "id": generar_id(),
            "tipo": tipo,
            "descripcion": descripcion,
            "gravedad": gravedad,
            "fecha": date.today().strftime("%d/%m/%Y"),
            "estado": estado
        }

        incidentes.append(incidente)

    print("\nEscenario de prueba cargado correctamente.")
    print("Se registraron 5 incidentes.")


# MENU PRINCIPAL
def menu_principal():

    while True:

        print("\n======================================")
        print(" SISTEMA DE CONTROL DE INCIDENTES")
        print("======================================")
        print("1. Registrar incidente")
        print("2. Consultar incidentes")
        print("3. Actualizar estado")
        print("4. Generar reporte")
        print("5. Cargar escenario de prueba")
        print("0. Salir")
        print("======================================")

        opcion = input("Seleccione una opcion: ")

        if opcion == "1":
            registrar_incidente()

        elif opcion == "2":
            consultar_incidentes()

        elif opcion == "3":
            actualizar_estado()

        elif opcion == "4":
            generar_reporte()

        elif opcion == "5":
            cargar_escenario_prueba()

        elif opcion == "0":
            print("Saliendo del sistema.")
            break

        else:
            print("Opcion no valida.")


# PROGRAMA PRINCIPAL
def main():

    print("SISTEMA DE CONTROL DE INCIDENTES DE SEGURIDAD")
    menu_principal()


main()

