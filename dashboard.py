# dashboard.py

import streamlit as st
import pandas as pd
import os
import glob
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np

# Importar las funciones de los módulos (Asegúrate de que estos archivos existan)
from scanner import escanear_web
from csv_generador import generar_csv_reporte
from diccionario import get_detalles_vulnerabilidad

# --- Configuración de la Aplicación Streamlit ---
st.set_page_config(
    page_title="Dashboard de Seguridad Web",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Funciones de Utilidad ---

def obtener_ultimo_reporte(directorio="reportes"):
    """Busca el archivo CSV más reciente en el directorio de reportes."""
    search_path = os.path.join(directorio, "reporte_seguridad_*.csv")
    archivos = glob.glob(search_path)
    
    if not archivos:
        return None
        
    archivos.sort(key=os.path.getmtime, reverse=True)
    return archivos[0]

def cargar_datos(ruta_csv):
    """Carga los datos del CSV en un DataFrame de Pandas."""
    try:
        df = pd.read_csv(ruta_csv)
        # Asegura el orden correcto de las severidades
        severidad_orden = ["Alta", "Media", "Baja", "Informativa"]
        df['SEVERIDAD'] = pd.Categorical(df['SEVERIDAD'], categories=severidad_orden, ordered=True)
        return df
    except Exception as e:
        st.error(f"Error al cargar el CSV: {e}")
        return pd.DataFrame() 

def extraer_fecha_reporte(ruta_csv):
    """
    Extrae y formatea la fecha del nombre del archivo CSV.
    """
    nombre_archivo = os.path.basename(ruta_csv)
    
    try:
        # Extraer la parte de la fecha y hora: YYYYmmdd_HHMMSS
        timestamp_completo = nombre_archivo.split('reporte_seguridad_')[-1].split('.')[0]
        
        formato_lectura = "%Y%m%d_%H%M%S" 
        fecha_formateada = datetime.strptime(timestamp_completo, formato_lectura).strftime("%d/%m/%Y a las %H:%M:%S")
        return fecha_formateada
    except (ValueError, IndexError):
        return "Fecha Desconocida (Error de Formato)"


# --- Interfaz de Usuario y Lógica Principal ---

st.title("🛡️ Scáner de Seguridad Web (HTTP Headers & Config)")
st.caption("Herramienta desarrollada en Python (Streamlit) para evaluar fallos comunes de configuración y cabeceras de seguridad.")

# =========================================================================
# 1. SIDEBAR: CONTROL DE ESCANEO
# =========================================================================

with st.sidebar:
    st.header("🔍 Iniciar Nuevo Escaneo")
    
    target_url = st.text_input(
        "URL objetivo (ej. https://google.com)",
        placeholder="https://tudominio.com"
    )
    
    if st.button("🚀 Iniciar Escaneo", type="primary"):
        if target_url:
            with st.spinner(f"Escaneando: {target_url}..."):
                resultados_escaneo = escanear_web(target_url)
                
                if resultados_escaneo and resultados_escaneo[0]['ID_VULN'] == 'CONEXION_FALLIDA':
                    st.error(f"¡Fallo de Conexión! No se pudo acceder a {target_url}. Verifica la URL o la conexión.")
                    st.stop()
                
                if resultados_escaneo:
                    ruta_csv = generar_csv_reporte(resultados_escaneo)
                    if ruta_csv:
                        st.success("¡Escaneo completado y reporte generado! Recargando dashboard...")
                        st.rerun() 
                    else:
                        st.info("Escaneo completado, no se encontraron vulnerabilidades que reportar.")
                else:
                    st.info("Escaneo completado, no se encontraron vulnerabilidades.")
        else:
            st.warning("Por favor, ingrese una URL válida para iniciar el escaneo.")

# =========================================================================
# 2. CUERPO PRINCIPAL: VISUALIZACIÓN DE DATOS Y DESCARGA
# =========================================================================

ruta_ultimo_csv = obtener_ultimo_reporte()

if ruta_ultimo_csv:
    df_reporte = cargar_datos(ruta_ultimo_csv)
    nombre_archivo_base = os.path.basename(ruta_ultimo_csv)
    
    fecha_reporte = extraer_fecha_reporte(ruta_ultimo_csv)
    
    col_header, col_download = st.columns([0.7, 0.3])
    
    with col_header:
        st.subheader(f"📊 Análisis del Último Reporte: {fecha_reporte}")
    
    if not df_reporte.empty:
        
        # --- BOTÓN DE DESCARGA ---
        with col_download:
            try:
                # Leer el archivo como bytes para el botón de descarga
                with open(ruta_ultimo_csv, "rb") as file:
                    st.download_button(
                        label="⬇️ Descargar Reporte CSV",
                        data=file,
                        file_name=nombre_archivo_base,
                        mime='text/csv',
                        type="secondary"
                    )
            except Exception as e:
                st.warning("No se pudo preparar el archivo para la descarga.")
        # -------------------------

        # --- FILAS DE MÉTRICAS (KPIs) ---
        col1, col2, col3, col4 = st.columns(4)
        
        col1.metric(label="Total de Hallazgos", value=len(df_reporte))
        
        alta_count = df_reporte[df_reporte['SEVERIDAD'] == 'Alta'].shape[0]
        media_count = df_reporte[df_reporte['SEVERIDAD'] == 'Media'].shape[0]

        col2.metric(label="🚨 Severidad ALTA", value=alta_count, delta=f"Riesgo Crítico")
        col3.metric(label="⚠️ Severidad MEDIA", value=media_count, delta=f"Riesgo Moderado")
        
        try:
            url_escaneada = df_reporte['URL_AFECTADA'].iloc[0].split('/')[2]
        except IndexError:
            url_escaneada = "N/A"
            
        col4.metric(label="Dominio Escaneado", value=url_escaneada)

        st.markdown("---")

        # --- GRÁFICO DE SEVERIDAD ---
        st.subheader("Distribución de Vulnerabilidades por Severidad")
        
        severidad_counts = df_reporte['SEVERIDAD'].value_counts().sort_index()
        
        fig, ax = plt.subplots(figsize=(8, 4))
        colores = {'Alta': '#E60000', 'Media': '#FFA500', 'Baja': '#FFCC00', 'Informativa': '#3399FF'}
        
        todas_severidades = ["Alta", "Media", "Baja", "Informativa"]
        severidad_counts = severidad_counts.reindex(todas_severidades, fill_value=0)
        
        severidad_counts.plot(
            kind='bar', 
            color=[colores.get(x, '#666666') for x in todas_severidades], 
            ax=ax
        )
        ax.set_title("Total de Fallos Encontrados por Nivel de Riesgo")
        ax.set_xlabel("Severidad")
        ax.set_ylabel("Cantidad")
        ax.tick_params(axis='x', rotation=0)
        st.pyplot(fig)

        st.markdown("---")
        
        # --- TABLA INTERACTIVA DE HALLAZGOS (USANDO SESSION STATE - CORRECCIÓN DEFINITIVA) ---
        st.subheader("Lista Detallada de Hallazgos")
        
        df_display = df_reporte.rename(columns={
            'ID_VULN': 'ID',
            'URL_AFECTADA': 'URL/Endpoint',
            'SEVERIDAD': 'Riesgo',
            'TIPO_FALLO': 'Descripción Breve'
        })
        
        # 1. Definimos el st.dataframe con una clave (key) para almacenar el resultado.
        st.dataframe(
            df_display,
            use_container_width=True,
            height=300,
            column_order=('Riesgo', 'ID', 'Descripción Breve', 'URL/Endpoint'),
            hide_index=True,
            selection_mode='single-row',
            key='selection_data' # <-- Clave de estado de sesión
        )

        # 2. Accedemos a la selección a través de st.session_state, donde es un diccionario.
        selection_dict = st.session_state.get('selection_data', {})
        
        # Lógica de selección para mostrar detalles
        # Verificamos que el diccionario de selección exista y contenga la lista de filas
        if selection_dict and 'selection' in selection_dict and 'rows' in selection_dict['selection']:
            selected_index_list = selection_dict['selection']['rows']
            
            if selected_index_list:
                selected_index = selected_index_list[0]
                selected_vuln_id = df_reporte.iloc[selected_index]['ID_VULN']
                
                detalles_completos = get_detalles_vulnerabilidad(selected_vuln_id)
                
                if detalles_completos:
                    st.markdown("---")
                    st.subheader(f"📖 Detalles y Solución para: **{detalles_completos['nombre']}**")
                    
                    st.markdown(f"**Riesgo Detectado:** `{selected_vuln_id}` en `{df_reporte.iloc[selected_index]['URL_AFECTADA']}`")
                    
                    st.info(f"**Descripción:** {detalles_completos['descripcion']}")
                    
                    st.success(f"**Solución Recomendada:** {detalles_completos['solucion']}")
                else:
                    st.warning("Detalles no encontrados en el diccionario para este ID.")

    else:
        st.warning(f"El reporte de {fecha_reporte} se cargó correctamente, pero no contiene datos de vulnerabilidades.")

else:
    st.info("No se han encontrado reportes de escaneo. Inicie un nuevo escaneo en la barra lateral para generar el primer reporte.")