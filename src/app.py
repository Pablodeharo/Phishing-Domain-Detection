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

@st.cache_resource
def load_model_and_scaler():
    rf_model = joblib.load("random_forest_phishing_model.joblib")
    scaler = joblib.load("scaler.joblib")
    return rf_model, scaler

rf_model, scaler = load_model_and_scaler()

def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    extract = tldextract.extract(url)

    # Longitud de la URL
    features['length_url'] = len(url)

    # Longitud del directorio
    features['directory_length'] = len(parsed_url.path)

    # Cantidad de slashes en el directorio
    features['qty_slash_directory'] = parsed_url.path.count('/')

    # Cantidad de puntos en el archivo
    features['qty_dot_file'] = len(re.findall(r'\.[^./]+$', parsed_url.path))

    # Longitud del dominio
    features['domain_length'] = len(extract.domain)

    # Otras características que podemos extraer directamente de la URL
    features['qty_dot_directory'] = parsed_url.path.count('.')
    features['qty_hyphen_directory'] = parsed_url.path.count('-')
    features['qty_at_directory'] = parsed_url.path.count('@')
    features['qty_and_directory'] = parsed_url.path.count('&')
    features['qty_comma_directory'] = parsed_url.path.count(',')
    features['qty_percent_directory'] = parsed_url.path.count('%')
    features['qty_dollar_directory'] = parsed_url.path.count('$')
    features['qty_slash_url'] = url.count('/')

    # Características que requieren solicitudes HTTP (ten cuidado con esto en producción)
    try:
        response = requests.get(url, timeout=5)
        features['time_response'] = response.elapsed.total_seconds()
        features['asn_ip'] = 0  # Esto requeriría una base de datos de ASN
        features['ttl_hostname'] = 0  # Esto requeriría una consulta DNS
    except:
        features['time_response'] = -1
        features['asn_ip'] = -1
        features['ttl_hostname'] = -1

    # Características que no podemos extraer fácilmente (usaremos valores predeterminados)
    features['time_domain_activation'] = -1
    features['time_domain_expiration'] = -1
    features['file_length'] = 0

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
        <a href="https://github.com/Pablodeharo" target="_blank">
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


def main():
    st.title('Detector de Phishing')

    add_banner_and_links()

    url = st.text_input('Introduce la URL a analizar:')

    if st.button('Predecir'):
        if url:
            try:
                input_data = extract_features(url)
                scaled_input = scaler.transform(input_data)
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
                st.write("Detalles del error:", e)
        else:
            st.warning('Por favor, introduce una URL.')

if __name__ == '__main__':
    main()