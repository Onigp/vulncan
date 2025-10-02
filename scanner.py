import requests
import re
from urllib.parse import urljoin
import sys

import urllib3
# Deshabilitamos las advertencias de conexión insegura.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from diccionario import get_detalles_vulnerabilidad

# Lista de archivos comunes que no deberían ser públicos
ARCHIVOS_SENSIBLES = [
    ".git/config",
    "wp-config.php.bak",
    "README.md",
    "test.php",
    "admin/backup.zip",
    "old.zip"
]

# Archivos que DEBEN ser públicos 
ARCHIVOS_PUBLICOS_ESPERADOS = ["robots.txt", "sitemap.xml"]


def format_hallazgo(url, vuln_id, detalles, tipo_fallo_override=None):
 #Estandariza el formato del resultado para el CSV
    return {
        "ID_VULN": vuln_id,
        "URL_AFECTADA": url,
        "SEVERIDAD": detalles['severidad'],
        "TIPO_FALLO": tipo_fallo_override if tipo_fallo_override else detalles['nombre']
    }


def revisar_cabeceras(url, response, resultados):
#Revisa la respuesta HTTP en busca de cabeceras de seguridad faltantes o inseguras
    
    headers = {k.lower(): v for k, v in response.headers.items()}
    
    # CABECERAS CRÍTICAS FALTANTES
    
    if 'strict-transport-security' not in headers:
        detalles = get_detalles_vulnerabilidad("MISSING_HSTS")
        if detalles: resultados.append(format_hallazgo(url, "MISSING_HSTS", detalles))
            
    has_csp_frame_ancestors = 'content-security-policy' in headers and 'frame-ancestors' in headers['content-security-policy'].lower()
    if 'x-frame-options' not in headers and not has_csp_frame_ancestors:
        detalles = get_detalles_vulnerabilidad("NO_XFO")
        if detalles: resultados.append(format_hallazgo(url, "NO_XFO", detalles))

    if 'x-content-type-options' not in headers or headers.get('x-content-type-options', '').lower() != 'nosniff':
        detalles = get_detalles_vulnerabilidad("NO_XCTO")
        if detalles: resultados.append(format_hallazgo(url, "NO_XCTO", detalles))

    if 'content-security-policy' not in headers:
        detalles = get_detalles_vulnerabilidad("MISSING_CSP")
        if detalles: resultados.append(format_hallazgo(url, "MISSING_CSP", detalles))

    if 'referrer-policy' not in headers:
        detalles = get_detalles_vulnerabilidad("NO_REFERRER_POLICY")
        if detalles: resultados.append(format_hallazgo(url, "NO_REFERRER_POLICY", detalles))
            
    # 2. FUGAS DE INFORMACIÓN 
    
    # Exposición de Software/Versión en cabeceras   
    if 'server' in headers and re.search(r'\d+\.\d+', headers['server']):
        detalles = get_detalles_vulnerabilidad("SERVER_INFO_EXPOSED")
        if detalles: 
            resultados.append(format_hallazgo(url, "SERVER_INFO_EXPOSED", detalles, f"Expone la cabecera Server: {headers['server']}"))

    if 'x-powered-by' in headers:
        detalles = get_detalles_vulnerabilidad("SERVER_INFO_EXPOSED")
        if detalles:
            resultados.append(format_hallazgo(url, "SERVER_INFO_EXPOSED", detalles, f"Expone la cabecera X-Powered-By: {headers['x-powered-by']}"))
            
    # Detección de Errores Verbosos
    if response.status_code >= 500 and re.search(r'stack trace|error at line|exception in|fatal error', response.text, re.IGNORECASE):
        detalles = get_detalles_vulnerabilidad("VERBOSE_ERRORS")
        if detalles: resultados.append(format_hallazgo(url, "VERBOSE_ERRORS", detalles))

    # COOKIES 
    for k, v in response.headers.items():
        if k.lower() == 'set-cookie':
            # Cookie sin Secure si es HTTPS
            if 'secure' not in v.lower() and url.startswith('https'):
                detalles = get_detalles_vulnerabilidad("INSECURE_COOKIE_SECURE")
                if detalles: resultados.append(format_hallazgo(url, "INSECURE_COOKIE_SECURE", detalles))
            # Cookie sin HttpOnly
            if 'httponly' not in v.lower():
                detalles = get_detalles_vulnerabilidad("INSECURE_COOKIE_HTTPONLY")
                if detalles: resultados.append(format_hallazgo(url, "INSECURE_COOKIE_HTTPONLY", detalles))


def revisar_archivos_sensibles(base_url, resultados):

    # Intenta acceder a URLs comunes donde se almacenan archivos sensibles

    for archivo in ARCHIVOS_SENSIBLES + ARCHIVOS_PUBLICOS_ESPERADOS:
        target_url = urljoin(base_url, archivo)
        try:
            res = requests.head(target_url, timeout=5, allow_redirects=True, verify=False)
            
            if res.status_code == 200:
                detalles = get_detalles_vulnerabilidad("EXPOSED_BACKUP_FILES")
                if detalles:
                    hallazgo = format_hallazgo(target_url, "EXPOSED_BACKUP_FILES", detalles)
                    
                    # ajuste de severidad para archivos esperados
                    if archivo in ARCHIVOS_PUBLICOS_ESPERADOS:
                        hallazgo["SEVERIDAD"] = "Informativa" 
                        hallazgo["TIPO_FALLO"] = f"Archivo accesible (esperado): {archivo} (200 OK)"
                    else:
                        hallazgo["TIPO_FALLO"] = f"Archivo sensible expuesto: {archivo} (200 OK)" 
                        
                    resultados.append(hallazgo)
                    
        except requests.exceptions.RequestException:
            pass

def escanear_web(url_objetivo):

    # Función principal que ejecuta el escaneo de vulnerabilidades.

    if not url_objetivo.startswith(('http://', 'https://')):
        url_objetivo = 'https://' + url_objetivo

    resultados = []
    
    if not url_objetivo:
        return resultados

    try:
        response = requests.get(url_objetivo, timeout=10, allow_redirects=True, verify=False)
        
        if response.status_code < 400:
            revisar_cabeceras(url_objetivo, response, resultados)
            revisar_archivos_sensibles(response.url, resultados)
        else:
            detalles_falla = get_detalles_vulnerabilidad("CONEXION_FALLIDA")
            return [format_hallazgo(url_objetivo, "CONEXION_FALLIDA", detalles_falla, f"Código de estado HTTP: {response.status_code}")]


    except requests.exceptions.RequestException as e:
        detalles_falla = get_detalles_vulnerabilidad("CONEXION_FALLIDA")
        return [format_hallazgo(url_objetivo, "CONEXION_FALLIDA", detalles_falla)]

    return resultados

# Ejemplo de ejecución
if __name__ == '__main__':
    target = input("Introduce la URL a escanear (ej. https://example.com): ")

    if target:
        print(f"[*] Iniciando escaneo básico de: {target}")
        reporte = escanear_web(target)
        
        if reporte and reporte[0]['ID_VULN'] != 'CONEXION_FALLIDA':
            print(f"[*] Escaneo completado. Encontrados {len(reporte)} hallazgos.")
            print("\n--- Reporte de Vulnerabilidades ---")
            for hallazgo in reporte:
                print(f"ID: {hallazgo['ID_VULN']} | Severidad: {hallazgo['SEVERIDAD']:<15} | Fallo: {hallazgo['TIPO_FALLO']:<50} | URL: {hallazgo['URL_AFECTADA']}")
        elif reporte and reporte[0]['ID_VULN'] == 'CONEXION_FALLIDA':
             print(f"[!] Error de Conexión: {reporte[0]['TIPO_FALLO']}")
        else:
            print("[*] Escaneo completado. No se encontraron fallos de seguridad.")
    else:
        print("URL no introducida. Terminando el script.")