import os
import json
import locale

# 获取系统语言
def get_system_language():
    try:
        return locale.getdefaultlocale()[0].split('_')[0]
    except:
        return 'en'

# 加载翻译文件
def load_translations():
    lang = get_system_language()
    translation_file = os.path.join(os.path.dirname(__file__), 'translations', f'{lang}.json')
    
    # 如果没有对应语言的翻译，使用英文
    if not os.path.exists(translation_file):
        translation_file = os.path.join(os.path.dirname(__file__), 'translations', 'en.json')
    
    with open(translation_file, 'r', encoding='utf-8') as f:
        return json.load(f)

# 翻译函数
def _(key):
    global _translations
    if '_translations' not in globals():
        try:
            _translations = load_translations()
        except:
            _translations = {}
    
    return _translations.get(key, key)
