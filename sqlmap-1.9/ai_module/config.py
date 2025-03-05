import os
import json
import configparser
import keyring
import getpass
from pathlib import Path

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'ai_config.ini')
ENV_KEY_NAME = 'SQLMAP_AI_KEY'
KEYRING_SERVICE = 'sqlmap'
KEYRING_USERNAME = 'ai_api_key'

def get_config_path():
    """
    返回配置文件和密钥的存储位置信息
    """
    result = f"配置文件位置: {os.path.abspath(CONFIG_FILE)}\n"
    
    # 添加密钥存储位置信息
    result += f"环境变量名称: {ENV_KEY_NAME}\n"
    result += f"系统密钥环服务名: {KEYRING_SERVICE}\n"
    result += f"系统密钥环用户名: {KEYRING_USERNAME}\n"
    
    # 检查当前使用的存储方式
    if ENV_KEY_NAME in os.environ:
        result += "当前API密钥存储方式: 环境变量\n"
    elif keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME):
        result += "当前API密钥存储方式: 系统密钥环\n"
    elif os.path.exists(CONFIG_FILE):
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        if 'API' in config and 'key' in config['API']:
            result += "当前API密钥存储方式: 配置文件 (不安全)\n"
    
    return result

def load_config():
    config = configparser.ConfigParser()
    
    # 默认配置
    config['API'] = {
        'openai_api_base': 'https://xiaohumini.site/v1',
        'openai_model': 'claude-3-5-sonnet-20241022',
        'openai_timeout': '30',
        'openai_temperature': '0.7',
        'openai_max_tokens': '2000',
        'openai_api_type': 'proxy',
        'openai_auth_type': 'bearer',
        'openai_auth_header': 'Authorization',
        'openai_auth_prefix': 'Bearer',
        'max_retries': '3'
    }
    
    config['CACHE'] = {
        'enabled': 'true',
        'expiry_days': '7'
    }
    
    config['FEATURES'] = {
        'smart_payload': 'true',
        'results_analysis': 'true',
        'vulnerability_explanation': 'true'
    }
    
    # 从配置文件加载
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config.read_file(f)
        except Exception as e:
            print(f"读取配置文件时出错: {e}")
            # 使用默认配置继续
    
    # 类型转换
    config['API']['openai_timeout'] = str(int(config['API']['openai_timeout']))
    config['API']['openai_max_tokens'] = str(int(config['API']['openai_max_tokens']))
    config['API']['max_retries'] = str(int(config['API']['max_retries']))
    
    return config

def save_config(config):
    try:
        # 确保配置目录存在
        config_dir = os.path.dirname(CONFIG_FILE)
        os.makedirs(config_dir, exist_ok=True)
        
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            config.write(f)
    except Exception as e:
        print(f"保存配置文件时出错: {e}")
        raise

def get_api_key():
    """
    按以下优先级获取API密钥：
    1. 环境变量
    2. 系统密钥环
    3. 配置文件
    """
    # 1. 检查环境变量
    env_key = os.environ.get(ENV_KEY_NAME)
    if env_key:
        return env_key
    
    # 2. 检查系统密钥环
    try:
        key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        if key:
            return key
    except Exception as e:
        print(f"从系统密钥环获取API密钥失败: {e}")
    
    # 3. 检查配置文件
    config = load_config()
    if 'API' in config and 'key' in config['API']:
        return config['API']['key']
    
    return None

def set_api_key(key=None):
    """
    设置API密钥，优先使用系统密钥环
    :param key: 可选的API密钥，如果未提供则交互式获取
    :return: bool 是否成功设置
    """
    if key is None:
        print("请输入您的API密钥 (输入将不会显示):")
        key = getpass.getpass()
    
    if not key:
        print("错误: API密钥不能为空")
        return False
    
    # 首先尝试使用系统密钥环
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, key)
        print("API密钥已安全保存到系统密钥环")
        return True
    except Exception as e:
        print(f"无法保存到系统密钥环: {e}")
        
        # 如果密钥环不可用，提供其他选项
        print("\n可选的存储方式:")
        print("1. 保存到配置文件 (不推荐)")
        print("2. 使用环境变量")
        print("3. 取消")
        
        choice = input("请选择 (1-3): ")
        
        if choice == "1":
            try:
                config = load_config()
                config['API']['key'] = key
                save_config(config)
                print("API密钥已保存到配置文件")
                print("警告: 这种存储方式不够安全，建议使用系统密钥环或环境变量")
                return True
            except Exception as e:
                print(f"保存到配置文件失败: {e}")
        elif choice == "2":
            print(f"\n请将以下命令添加到您的环境变量中:")
            print(f"export {ENV_KEY_NAME}='{key}'  # Linux/macOS")
            print(f"set {ENV_KEY_NAME}={key}  # Windows")
            return True
    
    return False

def remove_api_key():
    """
    移除所有存储的API密钥
    """
    removed = False
    
    # 1. 移除系统密钥环中的密钥
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
        print("已从系统密钥环移除API密钥")
        removed = True
    except:
        pass
    
    # 2. 移除配置文件中的密钥
    try:
        config = load_config()
        if 'key' in config['API']:
            del config['API']['key']
            save_config(config)
            print("已从配置文件移除API密钥")
            removed = True
    except:
        pass
    
    # 3. 提醒用户检查环境变量
    if ENV_KEY_NAME in os.environ:
        print(f"请记得手动移除环境变量 {ENV_KEY_NAME}")
        removed = True
    
    if not removed:
        print("未找到任何已存储的API密钥")
    
    return removed
