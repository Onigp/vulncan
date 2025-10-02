# 🛡️ Vulnescan: Escáner Básico de Seguridad Web (HTTP/Archivos)

Vulnescan es una herramienta sencilla y eficiente diseñada para auditar la configuración de seguridad básica de una aplicación web. Se especializa en la detección de **cabeceras HTTP faltantes** y la **exposición de archivos sensibles**, proporcionando un *dashboard* interactivo a través de Streamlit.

-----

## ✨ Características Principales

  * **Análisis de Cabeceras HTTP:** Verifica la presencia y configuración adecuada de defensas web clave, como:
      * **Strict-Transport-Security (HSTS)**
      * **Content-Security-Policy (CSP)**
      * **X-Frame-Options (XFO)**
  * **Detección de Fuga de Información:** Identifica la exposición de versiones de *software* (ej. cabeceras `X-Powered-By` o `Server`).
  * **Revisión de Archivos Expuestos:** Intenta acceder a rutas comunes donde se almacenan archivos sensibles, ajustando la severidad para archivos públicos esperados como `robots.txt`.
  * **Clasificación de Severidad:** Asigna niveles de riesgo (**Alta, Media, Baja, Informativa**) a cada hallazgo, facilitando la priorización de la corrección.
  * **Dashboard Interactivo:** Interfaz gráfica amigable construida con **Streamlit** para escanear, visualizar reportes en tiempo real y descargar los resultados.

-----

## ⚙️ Estructura del Proyecto

El proyecto se compone de los siguientes archivos clave:

| Archivo | Descripción |
| :--- | :--- |
| `scanner.py` | Contiene la lógica principal de escaneo, el manejo de peticiones HTTP, el seguimiento de redirecciones (`allow_redirects=True`) y el análisis de cabeceras y archivos. |
| `dashboard.py` | La interfaz gráfica construida con Streamlit. Maneja la entrada de URL, la ejecución del escáner, la visualización de la tabla de resultados y el botón de descarga CSV. |
| `diccionario.py` | Módulo crucial que define los detalles de cada vulnerabilidad (`ID_VULN`), su nombre, descripción y el **nivel de severidad** asignado (la base para la clasificación del riesgo). |
| `csv_generador.py` | Módulo auxiliar que transforma la lista de resultados del escáner en una cadena de texto en formato CSV, lista para ser descargada. |

-----

## 🚀 Instalación y Uso

### 1\. Requisitos e Instalación de Dependencias

Asegúrate de tener **Python** instalado (versión 3.8 o superior). Luego, instala las librerías necesarias:

```bash
pip install streamlit requests pandas urllib3
```

### 2\. Ejecutar la Aplicación

Una vez que tengas los archivos `scanner.py`, `dashboard.py`, `diccionario.py` y `csv_generador.py` en la misma carpeta, inicia el *dashboard* ejecutando el archivo principal de Streamlit:

```bash
streamlit run dashboard.py
```

La aplicación se abrirá automáticamente en tu navegador web (generalmente en `http://localhost:8501`).

### 3\. Flujo de Trabajo

1.  Introduce la URL del objetivo (ej. `https://ejemplo.com`) en el campo de texto.
2.  Haz clic en el botón **Escanear**.
3.  Los resultados se mostrarán en la tabla, organizados por severidad.
4.  Utiliza el botón **Descargar Reporte (CSV)** para guardar los hallazgos en formato de hoja de cálculo.

