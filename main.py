import datetime
import hashlib
import json
import math
import os
import shutil
import sys
import time


class EvaluadorSeguridad:
  """Módulo de evaluación avanzada de contraseñas y análisis de entropía de datos."""

  @staticmethod
  def calcular_entropia(password: str) -> float:
    """Calcula la entropía de Shannon (medida en bits) para determinar la aleatoriedad."""
    if not password:
      return 0.0

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)

    pool_size = 0
    if has_lower:
      pool_size += 26
    if has_upper:
      pool_size += 26
    if has_digits:
      pool_size += 10
    if has_symbols:
      pool_size += 32

    if pool_size == 0:
      return 0.0

    # Fórmula de Entropía: E = L * log2(R)
    entropia = len(password) * math.log2(pool_size)
    return round(entropia, 2)

  @staticmethod
  def generar_hashes(password: str) -> dict:
    """Genera huellas criptográficas en algoritmos estándar (MD5, SHA-1 y SHA-256)."""
    bytes_pass = password.encode('utf-8')
    return {
        'md5': hashlib.md5(bytes_pass).hexdigest(),
        'sha1': hashlib.sha1(bytes_pass).hexdigest(),
        'sha256': hashlib.sha256(bytes_pass).hexdigest(),
    }

  @classmethod
  def diagnosticar_clave(cls, password: str) -> dict:
    """Realiza una auditoría criptográfica completa de la credencial."""
    longitud = len(password)
    entropia = cls.calcular_entropia(password)
    hashes = cls.generar_hashes(password)

    tiene_mayus = any(c.isupper() for c in password)
    tiene_minus = any(c.islower() for c in password)
    tiene_num = any(c.isdigit() for c in password)
    tiene_simbolo = any(not c.isalnum() for c in password)

    if entropia < 40:
      nivel = 'CRÍTICO / DÉBIL'
      recomendacion = (
          'Cambiar de inmediato. Muy vulnerable a ataques de fuerza bruta y'
          ' diccionarios.'
      )
      color = '🔴'
    elif 40 <= entropia < 65:
      nivel = 'ACEPTABLE / MEDIO'
      recomendacion = (
          'Agregar mayor longitud y símbolos especiales ($#@!) para resistir'
          ' ataques.'
      )
      color = '🟡'
    else:
      nivel = 'ROBUSTO / ALTA SEGURIDAD'
      recomendacion = (
          'Excelente clave. Cumple con los estándares internacionales ISO 27001'
          ' y NIST.'
      )
      color = '🟢'

    return {
        'longitud': longitud,
        'entropia_bits': entropia,
        'nivel': nivel,
        'color': color,
        'detalles': {
            'Mayúsculas': tiene_mayus,
            'Minúsculas': tiene_minus,
            'Números': tiene_num,
            'Símbolos': tiene_simbolo,
        },
        'hashes': hashes,
        'recomendacion': recomendacion,
    }


class GestorMantenimiento:
  """Módulo de mantenimiento preventivo y respaldos de seguridad."""

  @staticmethod
  def auditoria_carpetas_criticas(ruta: str) -> dict:
    """Escanea directorios en busca de extensiones de ejecución potencial o riesgo."""
    if not os.path.exists(ruta):
      return {'error': 'La ruta especificada no existe.'}

    extensiones_riesgo = ['.exe', '.bat', '.vbs', '.scr', '.ps1', '.cmd', '.js']
    archivos_analizados = 0
    archivos_sospechosos = []
    peso_total_bytes = 0

    for root, _, files in os.walk(ruta):
      for file in files:
        archivos_analizados += 1
        filepath = os.path.join(root, file)
        try:
          peso_total_bytes += os.path.getsize(filepath)
        except OSError:
          pass

        _, ext = os.path.splitext(file)
        if ext.lower() in extensiones_riesgo:
          archivos_sospechosos.append(file)

    return {
        'ruta_analizada': os.path.abspath(ruta),
        'total_archivos': archivos_analizados,
        'archivos_riesgo_encontrados': len(archivos_sospechosos),
        'lista_riesgos': archivos_sospechosos[:5],
        'tamano_mb': round(peso_total_bytes / (1024 * 1024), 2),
    }

  @staticmethod
  def ejecutar_backup(
      ruta_origen: str, carpeta_destino: str = 'Backups_Seguros'
  ) -> dict:
    """Genera una copia de seguridad empaquetada en formato .ZIP."""
    if not os.path.exists(ruta_origen):
      return {'exito': False, 'mensaje': 'Ruta de origen no encontrada.'}

    if not os.path.exists(carpeta_destino):
      os.makedirs(carpeta_destino)

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    nombre_zip = f'Backup_TIC_{timestamp}'
    ruta_salida_zip = os.path.join(carpeta_destino, nombre_zip)

    try:
      archivo_generado = shutil.make_archive(
          ruta_salida_zip, 'zip', ruta_origen
      )
      tamano_mb = round(os.path.getsize(archivo_generado) / (1024 * 1024), 2)
      return {
          'exito': True,
          'archivo_zip': archivo_generado,
          'tamano_mb': tamano_mb,
          'fecha': timestamp,
      }
    except Exception as e:
      return {'exito': False, 'mensaje': str(e)}


class ReporteAuditoria:
  """Generador de informes técnicos estructurados en JSON."""

  @staticmethod
  def exportar_informe_json(
      datos_auditoria: dict, filename: str = 'informe_seguridad.json'
  ):
    with open(filename, 'w', encoding='utf-8') as f:
      json.dump(datos_auditoria, f, indent=4, ensure_ascii=False)
    return os.path.abspath(filename)


def main():
  print('=' * 65)
  print('      UNIVERSIDAD NACIONAL FEDERICO VILLARREAL (UNFV)')
  print('     Escuela Profesional de Ingeniería de Sistemas - TIC')
  print('=' * 65)
  print('   SISTEMA INTEGRAL DE DIAGNÓSTICO Y CIBERSEGURIDAD (v2.0 - PRO)')
  print('=' * 65)

  historial_auditoria = []

  while True:
    print('\n--- MENÚ DE AUDITORÍA Y SEGURIDAD INFORMÁTICA ---')
    print('1. Audit de Contraseñas (Análisis Criptográfico y Entropía)')
    print('2. Mantenimiento Preventivo (Auditoría de Directorios y Riesgos)')
    print('3. Ejecutar Copia de Seguridad Resguardada (Backup Automático)')
    print('4. Generar Informe Técnico de Diagnóstico (.JSON)')
    print('5. Salir del Sistema')

    opcion = input('\nIngrese una opción (1-5): ').strip()

    if opcion == '1':
      clave = input('\nIngrese la contraseña a auditar: ')
      print(
          'Analizando patrones criptográficos y calculando entropía de'
          ' Shannon...'
      )
      time.sleep(0.4)

      res = EvaluadorSeguridad.diagnosticar_clave(clave)
      historial_auditoria.append({'tipo': 'auditoria_clave', 'resultado': res})

      print(f"\nRESULTADO DE AUDITORÍA {res['color']}:")
      print(f"• Estado: {res['nivel']}")
      print(f"• Longitud: {res['longitud']} caracteres")
      print(f"• Entropía Criptográfica: {res['entropia_bits']} bits")
      print('• Complejidad de Caracteres:')
      for k, v in res['detalles'].items():
        print(f"   - {k}: {'✓ Sí' if v else '✗ No'}")
      print(f"• Hash SHA-256: {res['hashes']['sha256']}")
      print(f"• Recomendación TÉCNICA: {res['recomendacion']}")

    elif opcion == "2":
      ruta = input(
          "\nIngrese la ruta del directorio a inspeccionar (ENTER para"
          " directorio actual): "
      ).strip()
      if not ruta:
        ruta = "."
      res = GestorMantenimiento.auditoria_carpetas_criticas(ruta)
      historial_auditoria.append(
          {"tipo": "auditoria_directorio", "resultado": res}
      )

      if "error" in res:
        print(f"⚠️ Error: {res['error']}")
      else:
        print("\nAUDITORÍA DE DIRECTORIO FINALIZADA:")
        print(f"• Ruta Inspeccionada: {res['ruta_analizada']}")
        print(f"• Total de Archivos Evaluados: {res['total_archivos']}")
        print(f"• Peso Total del Directorio: {res['tamano_mb']} MB")
        print(
            "• Archivos Ejecutables / Potencial Riesgo:"
            f" {res['archivos_riesgo_encontrados']}"
        )

    elif opcion == "3":
      ruta_orig = input(
          "\nIngrese la ruta de la carpeta a respaldar ('.' para actual): "
      ).strip()
      if not ruta_orig:
        ruta_orig = "."
      res = GestorMantenimiento.ejecutar_backup(ruta_orig)
      historial_auditoria.append({"tipo": "backup", "resultado": res})

      if res["exito"]:
        print(f"\n🟢 RESPALDO GENERADO CON ÉXITO:")
        print(f"• Archivo Destino: {res['archivo_zip']}")
        print(f"• Tamaño Comprimido: {res['tamano_mb']} MB")

    elif opcion == "4":
      if not historial_auditoria:
        print("⚠️ No hay datos registrados en esta sesión para exportar.")
      else:
        ruta_json = ReporteAuditoria.exportar_informe_json(
            {"auditorias": historial_auditoria}
        )
        print(
            f"🟢 Reporte técnico exportado exitosamente en:\n{ruta_json}"
        )

    elif opcion == "5":
      print("\nSaliendo del Sistema de Auditoría TIC... ¡Hasta luego!")
      break


if __name__ == "__main__":
  main()
