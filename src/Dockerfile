FROM python:3.12-slim

WORKDIR /app

# Copia el archivo de requerimientos
COPY requirements.txt .

# Instala las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copia todos los archivos necesarios
COPY app.py .
COPY assets/ ./assets/
COPY random_forest_phishing_model.doblib .
COPY scaler.joblib .

# Comando para ejecutar la aplicación
CMD ["streamlit", "run", "app.py"]