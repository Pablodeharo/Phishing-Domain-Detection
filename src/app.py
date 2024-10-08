import streamlit as st 
import pandas as pd
import numpy as np
import joblib
import re
from urllib.parse import urlparse
import os
import base64
from importlib import resources
import tldextract
import requests
import sys
import logging
import traceback

#st.write("Python version:", sys.version)
#st.write("Current working directory:", os.getcwd())
#st.write("Contents of current directory:", os.listdir())

current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, "random_forest_phishing_model.joblib")
scaler_path = os.path.join(current_dir, "scaler.joblib")

@st.cache_resource
def load_model_and_scaler():
    try:
        rf_model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        return rf_model, scaler
    except Exception as e:
        st.error(f"Error al cargar el modelo o el scaler: {str(e)}")
        st.write("Ruta del modelo:", model_path)
        st.write("Ruta del scaler:", scaler_path)
        st.write("Contenido del directorio:", os.listdir(current_dir))
        raise e

# Intenta cargar el modelo y el scaler
try:
    rf_model, scaler = load_model_and_scaler()
except Exception as e:
    st.error("No se pudo cargar el modelo o el scaler. Verifica los logs para más detalles.")

def extract_features(url):
    features = {
        'length_url': 0,
        'directory_length': 0,
        'qty_slash_directory': 0,
        'qty_dot_file': 0,
        'domain_length': 0,
        'qty_dot_directory': 0,
        'qty_hyphen_directory': 0,
        'qty_at_directory': 0,
        'qty_and_directory': 0,
        'qty_comma_directory': 0,
        'qty_percent_directory': 0,
        'qty_dollar_directory': 0,
        'qty_slash_url': 0,
        'time_response': -1,
        'asn_ip': -1,
        'ttl_hostname': -1,
        'time_domain_activation': -1,
        'time_domain_expiration': -1,
        'file_length': 0,
        'qty_dollar_file': 0
    }

    try:
        parsed_url = urlparse(url)
        extract = tldextract.extract(url)

        features['length_url'] = len(url)
        features['directory_length'] = len(parsed_url.path)
        features['qty_slash_directory'] = parsed_url.path.count('/')
        features['qty_dot_file'] = len(re.findall(r'\.[^./]+$', parsed_url.path))
        features['domain_length'] = len(extract.domain)
        features['qty_dot_directory'] = parsed_url.path.count('.')
        features['qty_hyphen_directory'] = parsed_url.path.count('-')
        features['qty_at_directory'] = parsed_url.path.count('@')
        features['qty_and_directory'] = parsed_url.path.count('&')
        features['qty_comma_directory'] = parsed_url.path.count(',')
        features['qty_percent_directory'] = parsed_url.path.count('%')
        features['qty_dollar_directory'] = parsed_url.path.count('$')
        features['qty_slash_url'] = url.count('/')
        features['qty_dollar_file'] = parsed_url.path.count('$')

        try:
            response = requests.get(url, timeout=5)
            features['time_response'] = response.elapsed.total_seconds()
        except:
            pass  # Mantener el valor predeterminado si la solicitud falla

    except Exception as e:
        st.warning(f"No se pudieron extraer todas las características de la URL: {str(e)}")

    return pd.DataFrame([features])

def add_banner_and_links():
    # Lista de posibles rutas para el banner
    possible_paths = [
        "assets/banner.jpeg",
        "./assets/banner.jpeg",
        "../assets/banner.jpeg",
        os.path.join(os.path.dirname(__file__), "assets", "banner.jpeg")
    ]
    
    banner_found = False
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    image_bytes = f.read()
                st.image(image_bytes, use_column_width=True)
                banner_found = True
                break
            except Exception as e:
                pass

    if not banner_found:
        st.error("No se pudo encontrar o cargar el banner.")
        st.write("Directorio actual:", os.getcwd())
        st.write("Contenido del directorio:", os.listdir())
        if os.path.exists("assets"):
            st.write("Contenido de assets:", os.listdir("assets"))
        else:
            st.write("La carpeta 'assets' no existe en el directorio actual.")

    # Crear tres columnas para los botones
    col1, col2, col3 = st.columns(3)
    
    # Botón de GitHub
    with col1:
        github_html = f"""
        <a href="https://github.com/Pablodeharo/Phishing-Domain-Detection" target="_blank">
            <img src="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png" width="30" height="30">
            GitHub
        </a>
        """
        st.markdown(github_html, unsafe_allow_html=True)
    
    # Botón de LinkedIn
    with col2:
        linkedin_html = f"""
        <a href="https://www.linkedin.com/in/pablo-de-haro-pishoudt-0871972b6/" target="_blank">
            <img src="https://content.linkedin.com/content/dam/me/business/en-us/amp/brand-site/v2/bg/LI-Bug.svg.original.svg" width="30" height="30">
            LinkedIn
        </a>
        """
        st.markdown(linkedin_html, unsafe_allow_html=True)
    
    # Botón de Documentación (Notion)
    with col3:
        notion_html = f"""
        <a href="https://tiny-citrine-a6e.notion.site/Phishing-Domain-Detection-a9c3c58fc27746b586d43352e4ebe075" target="_blank">
            <img src="https://upload.wikimedia.org/wikipedia/commons/4/45/Notion_app_logo.png" width="30" height="30">
            Documentación
        </a>
        """
        st.markdown(notion_html, unsafe_allow_html=True)


logging.basicConfig(level=logging.INFO)
def main():
    try:
        logging.info("Iniciando la aplicación")
        st.title('Detector de Phishing')
        logging.info("Título mostrado")

        # Información de depuración
       # st.write("Python version:", sys.version)
       # st.write("Current working directory:", os.getcwd())
       # st.write("Contents of current directory:", os.listdir())

        add_banner_and_links()

        url = st.text_input('Introduce la URL a analizar:')

        if st.button('Predecir'):
            if url:
                try:
                    input_data = extract_features(url)
                    
                    # Verifica si el scaler está cargado correctamente
                    if 'scaler' not in globals():
                        raise Exception("El scaler no está cargado correctamente")

                    expected_columns = scaler.feature_names_in_
                    input_data = input_data.reindex(columns=expected_columns, fill_value=0)
                    
                    scaled_input = scaler.transform(input_data)

                    # Verifica si el modelo está cargado correctamente
                    if 'rf_model' not in globals():
                        raise Exception("El modelo no está cargado correctamente")

                    prediction = rf_model.predict(scaled_input)
                    proba = rf_model.predict_proba(scaled_input)

                    if prediction[0] == 1:
                        st.error('Esta URL es probablemente phishing.')
                    else:
                        st.success('Esta URL parece ser legítima.')

                    st.write(f'Probabilidad de phishing: {proba[0][1]:.2%}')

                    if st.checkbox('Mostrar características extraídas'):
                        st.write(input_data)
                except Exception as e:
                    st.error(f"Error al procesar la URL: {str(e)}")
                    st.write("Tipo de error:", type(e).__name__)
                    st.write("Detalles del error:", str(e))
                    st.write("Traceback:", traceback.format_exc())
                    logging.error(f"Error en el procesamiento: {str(e)}", exc_info=True)
            else:
                st.warning('Por favor, introduce una URL.')
        
        logging.info("Aplicación cargada completamente")
    except Exception as e:
        st.error(f"Error crítico en la aplicación: {str(e)}")
        logging.error(f"Error crítico: {str(e)}", exc_info=True)

if __name__ == '__main__':
    main()