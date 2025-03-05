import json
import os
from datetime import datetime, timedelta

CACHE_DIR = os.path.join(os.path.dirname(__file__), 'cache')
CACHE_EXPIRY = timedelta(days=7)  # 缓存有效期为7天

def get_cache(key):
    if not os.path.exists(CACHE_DIR):
        return None
    
    cache_file = os.path.join(CACHE_DIR, f"{key}.json")
    if not os.path.exists(cache_file):
        return None
    
    with open(cache_file, 'r') as f:
        data = json.load(f)
    
    if datetime.now() - datetime.fromisoformat(data['timestamp']) > CACHE_EXPIRY:
        os.remove(cache_file)
        return None
    
    return data['value']

def set_cache(key, value):
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    
    cache_file = os.path.join(CACHE_DIR, f"{key}.json")
    data = {
        'timestamp': datetime.now().isoformat(),
        'value': value
    }
    
    with open(cache_file, 'w') as f:
        json.dump(data, f)
