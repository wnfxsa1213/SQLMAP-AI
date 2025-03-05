from .cache import get_cache, set_cache
import hashlib
import requests
from .fallback import fallback_payload, fallback_analysis
from .config import load_config, get_api_key
import logging
import time
from requests.exceptions import RequestException
from lib.core.common import dataToStdout
import json
import os

logger = logging.getLogger('sqlmap.ai')

def get_proxy_settings(config):
    """获取代理设置"""
    proxy = config['API'].get('proxy', '')
    if proxy:
        return {
            'http': proxy,
            'https': proxy
        }
    return None

def get_auth_header(config, api_key, model_type='openai'):
    """获取认证头"""
    if model_type == 'openai':
        auth_type = config['API'].get('openai_auth_type', 'bearer').lower()
        auth_header = config['API'].get('openai_auth_header', 'Authorization')
        auth_prefix = config['API'].get('openai_auth_prefix', 'Bearer')
        
        if auth_type == 'bearer':
            return {auth_header: f"{auth_prefix} {api_key}"}
        elif auth_type == 'apikey':
            return {auth_header: api_key}
        else:
            raise ValueError(f"不支持的认证类型: {auth_type}")
    elif model_type == 'claude':
        return {
            "x-api-key": api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
    else:
        raise ValueError(f"不支持的模型类型: {model_type}")

def call_ai_model(prompt, model_override=None, max_retries=3, retry_delay=2):
    config = load_config()
    api_key = get_api_key()
    
    if not api_key:
        logger.error("API密钥未配置。请设置SQLMAP_AI_KEY环境变量或在配置文件中指定。")
        raise ValueError("API密钥未配置")
    
    # 确定使用哪个模型
    model_type = model_override or config['API'].get('default_model', 'openai')
    
    # 获取代理设置
    proxies = get_proxy_settings(config)
    
    # 检查缓存
    cache_enabled = config['CACHE'].getboolean('enabled')
    if cache_enabled:
        cache_key = hashlib.md5(prompt.encode()).hexdigest()
        cached_response = get_cache(cache_key)
        if cached_response:
            return cached_response
    
    retries = 0
    while retries < max_retries:
        try:
            if model_type.lower() == 'openai':
                # 获取认证头
                headers = get_auth_header(config, api_key, 'openai')
                headers["Content-Type"] = "application/json"
                
                data = {
                    "model": config['API']['openai_model'],
                    "messages": [
                        {"role": "system", "content": config['SYSTEM_PROMPTS']['openai']},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": float(config['API'].get('openai_temperature', 0.7)),
                    "max_tokens": int(config['API'].get('openai_max_tokens', 2000)),
                    "top_p": 1.0,
                    "frequency_penalty": 0.0,
                    "presence_penalty": 0.0
                }
                
                session = requests.Session()
                if proxies:
                    session.proxies = proxies
                
                # 构建完整的API URL
                api_base = config['API']['openai_api_base'].rstrip('/')
                api_url = f"{api_base}/chat/completions"
                
                response = session.post(
                    api_url,
                    headers=headers,
                    json=data,
                    timeout=float(config['API'].get('openai_timeout', 30))
                )
                
                if response.status_code == 200:
                    result = response.json()['choices'][0]['message']['content']
                else:
                    error_msg = f"API请求失败: 状态码 {response.status_code}"
                    try:
                        error_details = response.json()
                        if 'error' in error_details:
                            error_msg += f", 错误信息: {error_details['error']['message']}"
                    except:
                        error_msg += f", 响应内容: {response.text[:100]}"
                    raise Exception(error_msg)
            
            elif model_type.lower() == 'claude':
                # 获取认证头
                headers = get_auth_header(config, api_key, 'claude')
                
                system_prompt = config['SYSTEM_PROMPTS']['claude']
                formatted_prompt = f"{system_prompt}\n\nHuman: {prompt}\n\nAssistant:"
                
                data = {
                    "model": config['API']['claude_model'],
                    "prompt": formatted_prompt,
                    "max_tokens_to_sample": int(config['API'].get('claude_max_tokens', 2000)),
                    "temperature": float(config['API'].get('claude_temperature', 0.7))
                }
                
                session = requests.Session()
                if proxies:
                    session.proxies = proxies
                
                response = session.post(
                    config['API']['claude_api_base'],
                    headers=headers,
                    json=data,
                    timeout=float(config['API'].get('claude_timeout', 30))
                )
                
                if response.status_code == 200:
                    result = response.json()['completion']
                else:
                    raise Exception(f"Claude API请求失败: {response.status_code}")
            
            else:
                raise ValueError(f"不支持的模型类型: {model_type}")
            
            # 缓存结果
            if cache_enabled:
                set_cache(cache_key, result)
            return result
            
        except RequestException as e:
            if retries < max_retries - 1:
                logger.warning(f"请求失败 ({e})，{retry_delay}秒后重试 ({retries+1}/{max_retries})")
                time.sleep(retry_delay)
                retries += 1
            else:
                logger.error(f"请求失败，已达到最大重试次数: {e}")
                raise
        except Exception as e:
            if "rate_limit" in str(e).lower():
                # 处理速率限制
                retry_after = retry_delay
                logger.warning(f"API速率限制，等待 {retry_after} 秒后重试")
                time.sleep(retry_after)
                retries += 1
                continue
            logger.error(f"调用AI模型时发生错误: {str(e)}")
            raise
    
    # 如果所有重试都失败
    raise Exception(f"API请求失败，已达到最大重试次数 ({max_retries})")

def generate_smart_payload(dbms, vulnerability_type):
    try:
        dataToStdout("\n[*] 正在生成智能payload...")
        prompt = f"""
为{dbms}数据库生成一个针对{vulnerability_type}漏洞的SQL注入payload。
要求：
1. payload必须有效且能绕过常见的WAF
2. 使用适当的编码或混淆技术
3. 解释payload的工作原理
4. 提供可能的变体
"""
        result = call_ai_model(prompt)
        dataToStdout("\n[+] 生成完成\n")
        return result
    except Exception as e:
        dataToStdout(f"\n[-] 生成失败: {e}\n")
        logger.warning(f"AI payload生成失败: {e}")
        return fallback_payload(dbms, vulnerability_type)

def analyze_scan_results(results):
    try:
        prompt = f"""
分析以下sqlmap扫描结果并提供详细的安全建议:

{results}

请提供：
1. 发现漏洞的严重性评估
2. 可能的影响范围
3. 具体的修复步骤
4. 预防类似漏洞的最佳实践
"""
        return call_ai_model(prompt)
    except Exception as e:
        logger.warning(f"AI分析失败: {e}")
        return fallback_analysis(results)
