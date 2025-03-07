import os
import json
import configparser
import keyring
import getpass
import logging
from pathlib import Path

logger = logging.getLogger('sqlmap.ai')

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
    else:
        result += "未找到API密钥\n"
    
    return result

def load_config():
    """加载配置，使用默认值作为备份"""
    config = configparser.ConfigParser()
    
    # 默认配置
    config['API'] = {
        'openai_api_base': 'https://xiaohumini.site/v1',
        'openai_model': 'claude-3-5-sonnet-20241022',
        'openai_timeout': '30',
        'openai_temperature': '0.7',
        'openai_max_tokens': '2000',
        'openai_top_p': '1.0',
        'openai_frequency_penalty': '0.0',
        'openai_presence_penalty': '0.0',
        'openai_api_type': 'proxy',
        'openai_auth_type': 'bearer',
        'openai_auth_header': 'Authorization',
        'openai_auth_prefix': 'Bearer',
        'claude_api_base': 'https://api.anthropic.com/v1/',
        'claude_model': 'claude-3-opus-20240229',
        'claude_timeout': '30',
        'claude_temperature': '0.7',
        'claude_max_tokens': '2000',
        'max_retries': '3',
        'retry_delay': '2',
        'proxy': '',
        'default_model': 'openai'
    }
    
    config['CACHE'] = {
        'enabled': 'true',
        'expiry_days': '7',
        'directory': os.path.join(os.path.dirname(__file__), 'cache')
    }
    
    config['FEATURES'] = {
        'smart_payload': 'true',
        'results_analysis': 'true',
        'vulnerability_explanation': 'true'
    }
    
    config['SYSTEM_PROMPTS'] = {
        'openai': '你是一个SQL注入和Web安全专家，精通各种数据库的注入技术和防护方法。请提供准确、安全且实用的建议。',
        'claude': '\n\nHuman: 你是一个SQL注入和Web安全专家，精通各种数据库的注入技术和防护方法。请提供准确、安全且实用的建议。\n\nAssistant: 我理解了。我会基于我的SQL注入和Web安全专业知识为您提供帮助。'
    }
    
    config['TIMEOUTS'] = {
        'api_call_timeout': '30',
        'command_execution_timeout': '300',
        'command_execution_short_timeout': '60',
        'command_execution_long_timeout': '900'
    }
    
    # 从配置文件加载
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config.read_file(f)
                
            # 安全措施：如果配置文件中存在API密钥，将其移除
            if 'key' in config['API']:
                logger.warning("配置文件中发现API密钥，这是不安全的。将移除该密钥并保存更新后的配置文件。")
                # 临时保存密钥
                temp_key = config['API']['key']
                # 从配置中移除
                del config['API']['key']
                # 保存更新后的配置
                save_config(config)
                # 尝试将密钥保存到系统密钥环
                try:
                    if not keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME):
                        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, temp_key)
                        logger.info("已将API密钥从配置文件移动到系统密钥环")
                except Exception as e:
                    logger.warning(f"无法将API密钥保存到系统密钥环: {e}")
                    logger.info(f"请使用环境变量 {ENV_KEY_NAME} 设置API密钥")
        except Exception as e:
            logger.warning(f"读取配置文件时出错: {e}")
            # 使用默认配置继续
    
    # 确保所有必需的配置部分都存在
    for section in ['API', 'CACHE', 'FEATURES', 'SYSTEM_PROMPTS', 'TIMEOUTS']:
        if section not in config:
            config[section] = {}
    
    # 类型转换和验证
    for section in config.sections():
        for key, value in config[section].items():
            if key.endswith(('_timeout', '_max_tokens', 'max_retries', 'retry_delay', 'expiry_days')):
                try:
                    config[section][key] = str(int(value))
                except (ValueError, TypeError):
                    # 如果无法转换为整数，使用默认值
                    if section in config.defaults() and key in config.defaults()[section]:
                        config[section][key] = config.defaults()[section][key]
            elif key.endswith(('_temperature', '_top_p', '_frequency_penalty', '_presence_penalty')):
                try:
                    config[section][key] = str(float(value))
                except (ValueError, TypeError):
                    # 如果无法转换为浮点数，使用默认值
                    if section in config.defaults() and key in config.defaults()[section]:
                        config[section][key] = config.defaults()[section][key]
    
    return config

def save_config(config):
    """保存配置到文件"""
    try:
        # 确保配置目录存在
        config_dir = os.path.dirname(CONFIG_FILE)
        os.makedirs(config_dir, exist_ok=True)
        
        # 确保不保存API密钥
        if 'API' in config and 'key' in config['API']:
            del config['API']['key']
        
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            config.write(f)
        return True
    except Exception as e:
        logger.error(f"保存配置文件时出错: {e}")
        return False

def get_api_key():
    """
    按以下优先级获取API密钥：
    1. 环境变量
    2. 系统密钥环
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
        logger.warning(f"从系统密钥环获取API密钥失败: {e}")
    
    # 未找到API密钥
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
        logger.error("错误: API密钥不能为空")
        return False
    
    # 首先尝试使用系统密钥环
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, key)
        logger.info("API密钥已安全保存到系统密钥环")
        return True
    except Exception as e:
        logger.warning(f"无法保存到系统密钥环: {e}")
        
        # 如果密钥环不可用，提供环境变量选项
        print("\n系统密钥环不可用，请使用环境变量设置API密钥:")
        print(f"export {ENV_KEY_NAME}='{key}'  # Linux/macOS")
        print(f"set {ENV_KEY_NAME}={key}  # Windows")
        return False

def remove_api_key():
    """
    移除所有存储的API密钥
    """
    removed = False
    
    # 1. 移除系统密钥环中的密钥
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
        logger.info("已从系统密钥环移除API密钥")
        removed = True
    except:
        pass
    
    # 2. 提醒用户检查环境变量
    if ENV_KEY_NAME in os.environ:
        print(f"请记得手动移除环境变量 {ENV_KEY_NAME}")
        removed = True
    
    if not removed:
        logger.info("未找到任何已存储的API密钥")
    
    return removed

def validate_config():
    """
    验证配置的有效性，返回问题列表
    """
    config = load_config()
    issues = []
    
    # 检查API密钥
    if not get_api_key():
        issues.append("未配置API密钥")
    
    # 检查API基础URL
    if 'API' in config:
        if not config['API'].get('openai_api_base'):
            issues.append("未配置OpenAI API基础URL")
        if not config['API'].get('claude_api_base') and config['API'].get('default_model') == 'claude':
            issues.append("未配置Claude API基础URL")
    
    # 检查代理设置
    if 'API' in config and config['API'].get('proxy'):
        proxy = config['API'].get('proxy')
        import re
        proxy_pattern = r'^(http|https|socks[45]?)://([a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\])(:(\d+))?(/.*)?$'
        if not re.match(proxy_pattern, proxy):
            issues.append(f"代理URL格式不正确: {proxy}")
    
    # 检查缓存目录
    if 'CACHE' in config and config['CACHE'].getboolean('enabled', True):
        cache_dir = config['CACHE'].get('directory')
        if cache_dir and not os.path.exists(cache_dir):
            try:
                os.makedirs(cache_dir, exist_ok=True)
            except Exception as e:
                issues.append(f"无法创建缓存目录 {cache_dir}: {e}")
    
    return issues
