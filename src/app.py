import streamlit as st 
import pandas as pd
import numpy as np
import joblib
import re
from urllib.parse import urlparse
import os
import base64

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

    return features

def add_personal_banner_and_links():
    # Ruta relativa a tu banner
    image_path = "assets/banner.jpeg"
    
    # Imprime información de depuración
    st.write("Directorio de trabajo actual:", os.getcwd())
    st.write("Contenido del directorio:", os.listdir())
    
    # Verifica si la imagen existe
    if os.path.exists(image_path):
        with open(image_path, "rb") as img_file:
            img_data = base64.b64encode(img_file.read()).decode()
        
        st.markdown(
            f"""
            <style>
            .banner {{
                width: 100%;
                margin-top: 20px;
            }}
            .links {{
                display: flex;
                justify-content: center;
                gap: 20px;
                margin-top: 10px;
            }}
            .links a {{
                color: #4A4A4A;
                text-decoration: none;
                font-weight: bold;
            }}
            </style>
            <img src="data:image/jpeg;base64,{img_data}" class="banner">
            <div class="links">
                <a href="https://tiny-citrine-a6e.notion.site/Phishing-Domain-Detection-a9c3c58fc27746b586d43352e4ebe075" target="_blank">Documentación</a>
                <a href="https://www.linkedin.com/in/pablo-de-haro-pishoudt-0871972b6/" target="_blank">LinkedIn</a>
                <a href="https://github.com/Pablodeharo" target="_blank">GitHub</a>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.error(f"La imagen del banner no se encontró en la ruta: {image_path}")

def main():
    st.title('Detector de Phishing')

    # Input para la URL
    url = st.text_input('Introduce la URL a analizar:')

    if st.button('Predecir'):
        if url:
            # Extraer características
            input_data = extract_features(url)

            # Aplicar el scaling
            scaled_input = scaler.transform(input_data)

            # Hacer la predicción
            prediction = rf_model.predict(scaled_input)

            # Mostrar el resultado
            if prediction[0] == 1:
                st.error('Esta URL es probablemente phishing.')
            else:
                st.success('Esta URL parece ser legítima.')

            # Mostrar la probabilidad
            proba = rf_model.predict_proba(scaled_input)
            st.write(f'Probabilidad de phishing: {proba[0][1]:.2%}')

            # Mostrar las características extraídas (opcional)
            if st.checkbox('Mostrar características extraídas'):
                st.write(input_data)
        else:
            st.warning('Por favor, introduce una URL.')
    
    # Añadir el banner personal y los enlaces al final
    add_personal_banner_and_links()

if __name__ == '__main__':
    main()