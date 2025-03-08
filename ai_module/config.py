import os
import json
import configparser
import keyring
import getpass
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

# 设置日志记录器
logger = logging.getLogger('sqlmap.ai')

# 常量定义
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'ai_config.ini')
ENV_KEY_NAME = 'SQLMAP_AI_KEY'
KEYRING_SERVICE = 'sqlmap'
KEYRING_USERNAME = 'ai_api_key'

# 默认配置值
DEFAULT_CONFIG = {
    'API': {
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
        'max_retries': '3',
        'retry_delay': '2',
        'proxy': '',
        'default_model': 'openai'
    },
    'CACHE': {
        'enabled': 'true',
        'expiry_days': '7',
        'directory': None  # 将在运行时设置
    },
    'FEATURES': {
        'smart_payload': 'true',
        'results_analysis': 'true',
        'vulnerability_explanation': 'true'
    },
    'SYSTEM_PROMPTS': {
        'openai': '你是一个SQL注入和Web安全专家，精通各种数据库的注入技术和防护方法。请提供准确、安全且实用的建议。',
        'claude': '\n\nHuman: 你是一个SQL注入和Web安全专家，精通各种数据库的注入技术和防护方法。请提供准确、安全且实用的建议。\n\nAssistant: 我理解了。我会基于我的SQL注入和Web安全专业知识为您提供帮助。'
    },
    'TIMEOUTS': {
        'api_call_timeout': '30',
        'command_execution_timeout': '300',
        'command_execution_short_timeout': '60',
        'command_execution_long_timeout': '900'
    }
}

def get_config_path() -> str:
    """
    返回配置文件和密钥的存储位置信息
    
    返回:
        描述配置和密钥存储位置的字符串
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

def _set_default_values(config: configparser.ConfigParser) -> None:
    """
    设置默认配置值
    
    参数:
        config: 配置解析器对象
    """
    for section, options in DEFAULT_CONFIG.items():
        if section not in config:
            config[section] = {}
        
        for key, value in options.items():
            # 特殊处理缓存目录路径
            if section == 'CACHE' and key == 'directory' and value is None:
                config[section][key] = os.path.join(os.path.dirname(__file__), 'cache')
            elif key not in config[section]:
                config[section][key] = value

def _validate_types(config: configparser.ConfigParser) -> None:
    """
    验证并转换配置值的类型
    
    参数:
        config: 配置解析器对象
    """
    # 定义需要验证的配置类型
    int_keys = ['_timeout', '_max_tokens', 'max_retries', 'retry_delay', 'expiry_days']
    float_keys = ['_temperature', '_top_p', '_frequency_penalty', '_presence_penalty']
    
    for section in config.sections():
        for key, value in list(config[section].items()):
            # 整数类型
            if any(key.endswith(suffix) for suffix in int_keys):
                try:
                    config[section][key] = str(int(value))
                except (ValueError, TypeError):
                    logger.warning(f"配置项 {section}.{key} 值 '{value}' 不是有效的整数，使用默认值")
                    if section in DEFAULT_CONFIG and key in DEFAULT_CONFIG[section]:
                        config[section][key] = DEFAULT_CONFIG[section][key]
            
            # 浮点数类型
            elif any(key.endswith(suffix) for suffix in float_keys):
                try:
                    config[section][key] = str(float(value))
                except (ValueError, TypeError):
                    logger.warning(f"配置项 {section}.{key} 值 '{value}' 不是有效的浮点数，使用默认值")
                    if section in DEFAULT_CONFIG and key in DEFAULT_CONFIG[section]:
                        config[section][key] = DEFAULT_CONFIG[section][key]

def load_config() -> configparser.ConfigParser:
    """
    加载配置，使用默认值作为备份
    
    返回:
        配置解析器对象
    """
    config = configparser.ConfigParser()
    
    # 设置默认配置值
    _set_default_values(config)
    
    # 从配置文件加载
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config.read_file(f)
            
            # 安全措施：检查并移除配置文件中的API密钥
            if 'API' in config and 'key' in config['API']:
                logger.warning("配置文件中发现API密钥，这是不安全的。将移除该密钥并保存更新后的配置文件。")
                try:
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
                    logger.error(f"处理配置文件中的API密钥时出错: {e}")
        except Exception as e:
            logger.warning(f"读取配置文件时出错: {e}")
            logger.info("将使用默认配置")
            # 重置为默认配置
            config = configparser.ConfigParser()
            _set_default_values(config)
    
    # 确保所有必需的配置部分都存在
    for section in DEFAULT_CONFIG.keys():
        if section not in config:
            config[section] = {}
    
    # 验证配置类型并转换
    _validate_types(config)
    
    # 环境变量覆盖配置
    _apply_environment_variables(config)
    
    return config

def _apply_environment_variables(config: configparser.ConfigParser) -> None:
    """
    应用环境变量覆盖配置
    
    参数:
        config: 配置解析器对象
    """
    # 缓存设置
    if 'SQLMAP_AI_CACHE_DIR' in os.environ:
        config['CACHE']['directory'] = os.environ['SQLMAP_AI_CACHE_DIR']
    
    if 'SQLMAP_AI_CACHE_EXPIRY' in os.environ:
        try:
            expiry = int(os.environ['SQLMAP_AI_CACHE_EXPIRY'])
            config['CACHE']['expiry_days'] = str(expiry)
        except (ValueError, TypeError):
            logger.warning(f"环境变量 SQLMAP_AI_CACHE_EXPIRY 值 '{os.environ['SQLMAP_AI_CACHE_EXPIRY']}' 不是有效的整数")
    
    # 调试模式
    if 'SQLMAP_AI_DEBUG' in os.environ:
        debug_value = os.environ['SQLMAP_AI_DEBUG'].lower()
        if debug_value in ('1', 'true', 'yes', 'y'):
            if 'DEBUG' not in config:
                config['DEBUG'] = {}
            config['DEBUG']['enabled'] = 'true'
            
            # 设置日志级别
            logger.setLevel(logging.DEBUG)
            
            # 添加控制台处理器（如果尚未添加）
            if not logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                handler.setFormatter(formatter)
                logger.addHandler(handler)
    
    # API超时
    if 'SQLMAP_AI_TIMEOUT' in os.environ:
        try:
            timeout = int(os.environ['SQLMAP_AI_TIMEOUT'])
            config['API']['openai_timeout'] = str(timeout)
            config['API']['claude_timeout'] = str(timeout)
        except (ValueError, TypeError):
            logger.warning(f"环境变量 SQLMAP_AI_TIMEOUT 值 '{os.environ['SQLMAP_AI_TIMEOUT']}' 不是有效的整数")

def save_config(config: configparser.ConfigParser) -> bool:
    """
    保存配置到文件
    
    参数:
        config: 配置解析器对象
        
    返回:
        是否成功保存
    """
    try:
        # 确保配置目录存在
        config_dir = os.path.dirname(CONFIG_FILE)
        os.makedirs(config_dir, exist_ok=True)
        
        # 确保不保存API密钥
        if 'API' in config and 'key' in config['API']:
            del config['API']['key']
        
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            config.write(f)
        
        logger.info(f"配置已保存到 {CONFIG_FILE}")
        return True
    except Exception as e:
        logger.error(f"保存配置文件时出错: {e}")
        return False

def get_api_key() -> Optional[str]:
    """
    按以下优先级获取API密钥：
    1. 环境变量
    2. 系统密钥环
    
    返回:
        API密钥或None
    """
    # 1. 检查环境变量
    env_key = os.environ.get(ENV_KEY_NAME)
    if env_key:
        logger.debug("从环境变量获取API密钥")
        return env_key
    
    # 2. 检查系统密钥环
    try:
        key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        if key:
            logger.debug("从系统密钥环获取API密钥")
            return key
    except Exception as e:
        logger.warning(f"从系统密钥环获取API密钥失败: {e}")
    
    # 未找到API密钥
    logger.warning("未找到API密钥，请使用set_api_key()设置或通过环境变量提供")
    return None

def set_api_key(key: Optional[str] = None) -> bool:
    """
    设置API密钥，优先使用系统密钥环
    
    参数:
        key: 可选的API密钥，如果未提供则交互式获取
        
    返回:
        是否成功设置
    """
    if key is None:
        try:
            print("请输入您的API密钥 (输入将不会显示):")
            key = getpass.getpass()
        except Exception as e:
            logger.error(f"获取API密钥输入失败: {e}")
            return False
    
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

def remove_api_key() -> bool:
    """
    移除所有存储的API密钥
    
    返回:
        是否成功移除任何密钥
    """
    removed = False
    
    # 1. 移除系统密钥环中的密钥
    try:
        if keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME):
            keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
            logger.info("已从系统密钥环移除API密钥")
            removed = True
    except Exception as e:
        logger.warning(f"从系统密钥环移除API密钥失败: {e}")
    
    # 2. 提醒用户检查环境变量
    if ENV_KEY_NAME in os.environ:
        print(f"请记得手动移除环境变量 {ENV_KEY_NAME}:")
        print(f"unset {ENV_KEY_NAME}  # Linux/macOS")
        print(f"set {ENV_KEY_NAME}=  # Windows")
        removed = True
    
    if not removed:
        logger.info("未找到任何已存储的API密钥")
    
    return removed

def validate_config() -> List[str]:
    """
    验证配置的有效性，返回问题列表
    
    返回:
        问题描述列表
    """
    config = load_config()
    issues = []
    
    # 检查API密钥
    if not get_api_key():
        issues.append("未配置API密钥")
    
    # 检查必需的API配置
    if 'API' in config:
        if not config['API'].get('openai_api_base'):
            issues.append("未配置OpenAI API基础URL")
        if not config['API'].get('claude_api_base') and config['API'].get('default_model') == 'claude':
            issues.append("未配置Claude API基础URL")
        
        # 验证模型配置
        if not config['API'].get('openai_model'):
            issues.append("未配置OpenAI模型名称")
        if not config['API'].get('claude_model') and config['API'].get('default_model') == 'claude':
            issues.append("未配置Claude模型名称")
    
    # 检查代理设置
    if 'API' in config and config['API'].get('proxy'):
        proxy = config['API'].get('proxy')
        proxy_pattern = r'^(http|https|socks[45]?)://([a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\])(:(\d+))?(/.*)?$'
        if not re.match(proxy_pattern, proxy):
            issues.append(f"代理URL格式不正确: {proxy}")
    
    # 检查缓存目录
    if 'CACHE' in config and config['CACHE'].getboolean('enabled', True):
        cache_dir = config['CACHE'].get('directory')
        if not cache_dir:
            issues.append("启用了缓存但未配置缓存目录")
        elif not os.path.exists(cache_dir):
            try:
                os.makedirs(cache_dir, exist_ok=True)
                logger.info(f"已创建缓存目录: {cache_dir}")
            except Exception as e:
                issues.append(f"无法创建缓存目录 {cache_dir}: {e}")
        
        # 验证缓存过期时间
        try:
            expiry_days = int(config['CACHE'].get('expiry_days', '7'))
            if expiry_days < 1:
                issues.append(f"缓存过期天数 ({expiry_days}) 必须大于0")
        except (ValueError, TypeError):
            issues.append(f"缓存过期时间 '{config['CACHE'].get('expiry_days')}' 不是有效的整数")
    
    # 检查超时配置
    if 'API' in config:
        try:
            timeout = int(config['API'].get('openai_timeout', '30'))
            if timeout < 5:
                issues.append(f"API超时时间 ({timeout}) 可能过短，建议至少5秒")
        except (ValueError, TypeError):
            issues.append(f"API超时时间 '{config['API'].get('openai_timeout')}' 不是有效的整数")
    
    return issues

def get_config_value(section: str, key: str, default: Any = None) -> Any:
    """
    获取配置值，提供类型转换功能
    
    参数:
        section: 配置节名称
        key: 配置项名称
        default: 默认值
        
    返回:
        配置值（自动转换为适当的类型）
    """
    config = load_config()
    
    if section not in config or key not in config[section]:
        return default
    
    value = config[section][key]
    
    # 尝试转换为合适的类型
    if key.endswith(('_timeout', '_max_tokens', 'max_retries', 'retry_delay', 'expiry_days')):
        try:
            return int(value)
        except (ValueError, TypeError):
            return default if default is not None else value
    elif key.endswith(('_temperature', '_top_p', '_frequency_penalty', '_presence_penalty')):
        try:
            return float(value)
        except (ValueError, TypeError):
            return default if default is not None else value
    elif key.endswith(('enabled', 'debug')):
        return config[section].getboolean(key, default if default is not None else False)
    else:
        return value

def set_config_value(section: str, key: str, value: Any) -> bool:
    """
    设置配置值
    
    参数:
        section: 配置节名称
        key: 配置项名称
        value: 配置值
        
    返回:
        是否成功设置
    """
    try:
        config = load_config()
        
        if section not in config:
            config[section] = {}
        
        # 转换为字符串（configparser需要）
        config[section][key] = str(value)
        
        # 保存配置
        return save_config(config)
    except Exception as e:
        logger.error(f"设置配置值时出错: {e}")
        return False

def get_debug_mode() -> bool:
    """
    获取调试模式状态
    
    返回:
        是否启用调试模式
    """
    return get_config_value('DEBUG', 'enabled', False) or 'SQLMAP_AI_DEBUG' in os.environ

def check_api_credentials() -> Dict[str, bool]:
    """
    检查API凭据配置状态
    
    返回:
        包含不同API设置状态的字典
    """
    config = load_config()
    api_key = get_api_key()
    
    return {
        'api_key_configured': api_key is not None,
        'openai_api_configured': bool(config['API'].get('openai_api_base')),
        'claude_api_configured': bool(config['API'].get('claude_api_base')),
        'proxy_configured': bool(config['API'].get('proxy')),
        'current_model': config['API'].get('default_model', 'openai')
    }
