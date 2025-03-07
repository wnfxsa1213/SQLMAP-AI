import json
import os
import re
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from .config import load_config

logger = logging.getLogger('sqlmap.ai')

# 默认设置
DEFAULT_CACHE_DIR = os.path.join(os.path.dirname(__file__), 'cache')
DEFAULT_CACHE_EXPIRY = timedelta(days=7)  # 默认缓存有效期为7天

def get_cache_directory(config=None):
    """获取缓存目录，支持自定义路径"""
    if config is None:
        config = load_config()
    
    # 优先使用环境变量
    env_cache_dir = os.environ.get('SQLMAP_AI_CACHE_DIR')
    if env_cache_dir:
        cache_dir = env_cache_dir
    else:
        # 从配置获取或使用默认值
        cache_dir = config['CACHE'].get('directory', DEFAULT_CACHE_DIR)
    
    # 确保目录存在
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir

def get_cache_expiry(config=None):
    """获取缓存过期时间设置"""
    if config is None:
        config = load_config()
    
    # 优先使用环境变量
    env_expiry = os.environ.get('SQLMAP_AI_CACHE_EXPIRY')
    if env_expiry:
        try:
            return timedelta(days=int(env_expiry))
        except (ValueError, TypeError):
            logger.warning(f"无效的缓存过期时间环境变量值: {env_expiry}，使用默认值")
    
    # 从配置获取或使用默认值
    try:
        expiry_days = int(config['CACHE'].get('expiry_days', '7'))
        return timedelta(days=expiry_days)
    except (ValueError, TypeError):
        logger.warning("无效的缓存过期时间配置，使用默认值")
        return DEFAULT_CACHE_EXPIRY

def get_cache(key):
    """获取缓存，考虑过期时间"""
    config = load_config()
    cache_dir = get_cache_directory(config)
    cache_expiry = get_cache_expiry(config)
    
    cache_file = os.path.join(cache_dir, f"{key}.json")
    if not os.path.exists(cache_file):
        return None
    
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 检查缓存是否过期
        timestamp = datetime.fromisoformat(data['timestamp'])
        if datetime.now() - timestamp > cache_expiry:
            logger.debug(f"缓存已过期: {key}")
            try:
                os.remove(cache_file)
            except OSError as e:
                logger.debug(f"无法删除过期缓存文件: {e}")
            return None
        
        return data['value']
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"缓存文件损坏: {cache_file}, {e}")
        try:
            os.remove(cache_file)
        except OSError:
            pass
        return None
    except Exception as e:
        logger.warning(f"读取缓存时出错: {e}")
        return None

def set_cache(key, value, custom_expiry=None):
    """设置缓存，支持自定义过期时间"""
    config = load_config()
    cache_dir = get_cache_directory(config)
    
    try:
        cache_file = os.path.join(cache_dir, f"{key}.json")
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'value': value,
            'expires_at': (datetime.now() + (custom_expiry or get_cache_expiry(config))).isoformat()
        }
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            
        return True
    except Exception as e:
        logger.warning(f"设置缓存时出错: {e}")
        return False

def clear_cache(older_than=None):
    """
    清理缓存
    older_than: 可选的timedelta对象，指定要清理多久之前的缓存
    返回已清理的文件数量
    """
    config = load_config()
    cache_dir = get_cache_directory(config)
    count = 0
    
    try:
        # 如果未指定时间，使用缓存过期时间配置
        if older_than is None:
            older_than = get_cache_expiry(config)
        
        cutoff_time = datetime.now() - older_than
        
        for file in os.listdir(cache_dir):
            if not file.endswith('.json'):
                continue
                
            file_path = os.path.join(cache_dir, file)
            file_stat = os.stat(file_path)
            file_time = datetime.fromtimestamp(file_stat.st_mtime)
            
            # 检查文件修改时间
            if file_time < cutoff_time:
                try:
                    # 尝试读取文件中的实际过期时间
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if 'expires_at' in data:
                            expires_at = datetime.fromisoformat(data['expires_at'])
                            if datetime.now() < expires_at:
                                # 文件未过期，跳过
                                continue
                except:
                    # 读取失败，默认清理
                    pass
                    
                # 删除过期文件
                try:
                    os.remove(file_path)
                    count += 1
                except OSError as e:
                    logger.warning(f"无法删除缓存文件 {file}: {e}")
                    
        return count
    except Exception as e:
        logger.warning(f"清理缓存时出错: {e}")
        return count

def get_cache_stats():
    """获取缓存统计信息"""
    config = load_config()
    cache_dir = get_cache_directory(config)
    
    try:
        all_files = [f for f in os.listdir(cache_dir) if f.endswith('.json')]
        total_size = sum(os.path.getsize(os.path.join(cache_dir, f)) for f in all_files)
        
        # 计算过期文件
        expired_count = 0
        cache_expiry = get_cache_expiry(config)
        cutoff_time = datetime.now() - cache_expiry
        
        for file in all_files:
            file_path = os.path.join(cache_dir, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    timestamp = datetime.fromisoformat(data['timestamp'])
                    if datetime.now() - timestamp > cache_expiry:
                        expired_count += 1
            except:
                # 无法读取，可能损坏
                expired_count += 1
                
        return {
            'total_files': len(all_files),
            'expired_files': expired_count,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'cache_directory': cache_dir,
            'expiry_days': cache_expiry.days
        }
    except Exception as e:
        logger.warning(f"获取缓存统计时出错: {e}")
        return {
            'error': str(e),
            'cache_directory': cache_dir
        }
