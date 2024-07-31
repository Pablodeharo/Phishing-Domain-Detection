import joblib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import pandas as pd
from .feature_extractor import extract_features

# Cargar el modelo y el scaler
model = joblib.load('detector/models/random_forest_phishing_model.joblib')
scaler = joblib.load('detector/models/scaler.joblib')

@csrf_exempt
def predict(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data.get('url')
            if not url:
                return JsonResponse({'error': 'URL is required'}, status=400)

            # Extraer características de la URL
            features = extract_features(url)

            # Asegurarse de que las características estén en el orden correcto
            feature_order = [
                'directory_length', 'time_domain_activation', 'qty_dollar_directory',
                'qty_slash_directory', 'qty_dot_file', 'length_url', 'ttl_hostname',
                'time_response', 'asn_ip', 'qty_slash_url', 'qty_dot_directory',
                'qty_hyphen_directory', 'qty_at_directory', 'qty_and_directory',
                'qty_comma_directory', 'qty_percent_directory', 'qty_dollar_file',
                'file_length', 'time_domain_expiration', 'domain_length'
            ]
            
            # Crear un DataFrame con los datos extraídos
            df = pd.DataFrame([{key: features.get(key, 0) for key in feature_order}])
            
            # Escalar los datos
            scaled_data = scaler.transform(df)
            
            # Hacer la predicción
            prediction = model.predict(scaled_data)
            probability = model.predict_proba(scaled_data)[0][1]
            
            return JsonResponse({
                'url': url,
                'is_phishing': bool(prediction[0]),
                'phishing_probability': float(probability),
                'features': features
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=405)
