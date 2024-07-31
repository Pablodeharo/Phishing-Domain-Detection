import re
from urllib.parse import urlparse
import tldextract
import requests
from datetime import datetime

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