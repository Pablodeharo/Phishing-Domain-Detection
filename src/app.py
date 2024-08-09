import streamlit as st 
import pandas as pd
import numpy as np
import joblib
import re
from urllib.parse import urlparse
import os
import base64

def add_personal_banner():
    # Ruta específica a tu banner
    image_path = r"C:\Users\lenovo\Desktop\Phishing Domain Detection\Phishing Domain Detection\src\assets\banner.jpeg"
    
    # Verifica si la imagen existe
    if os.path.exists(image_path):
        st.markdown(
            f"""
            <style>
            .banner {{
                width: 100%;
                margin-top: 20px;
            }}
            </style>
            <img src="data:image/jpeg;base64,{get_image_base64(image_path)}" class="banner">
            """,
            unsafe_allow_html=True
        )
    else:
        st.error("La imagen del banner no se encontró.")

def get_image_base64(image_path):
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

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
    
    # Añadir el banner personal al final
    add_personal_banner()

if __name__ == '__main__':
    main()