from .cache import get_cache, set_cache
import hashlib
import requests
import re
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
    """获取并验证代理设置"""
    proxy = config['API'].get('proxy', '')
    if proxy:
        # 验证代理URL格式
        proxy_pattern = r'^(http|https|socks[45]?)://([a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\])(:(\d+))?(/.*)?$'
        if not re.match(proxy_pattern, proxy):
            logger.warning(f"代理URL格式不正确: {proxy}，将不使用代理")
            return None
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

def call_ai_model(
    prompt, 
    model_override=None, 
    api_key=None,       # 新增api_key参数
    config=None,       # 新增config参数
    max_retries=3, 
    retry_delay=2
):
    # 如果未传入config则加载默认配置
    config = config or load_config()  
    # 如果未传入api_key则自动获取
    api_key = api_key or get_api_key()  
    
    if not api_key:
        logger.error("API密钥未配置。请设置SQLMAP_AI_KEY环境变量或在系统密钥环中指定。")
        raise ValueError("API密钥未配置")
    
    # 确保model_type参数正确获取
    model_type = (model_override or config['API'].get('default_model', 'openai')).lower()
    
    # 验证模型类型
    if model_type not in ('openai', 'claude'):
        raise ValueError(f"不支持的模型类型: {model_type}")
    
    # 获取代理设置
    proxies = get_proxy_settings(config)
    
    # 检查缓存 - 使用更完善的缓存键生成
    cache_enabled = config['CACHE'].getboolean('enabled')
    if cache_enabled:
        # 将模型和温度等关键参数也包含在缓存键中
        cache_data = {
            'prompt': prompt,
            'model': model_type,
            'temperature': config['API'].get(f'{model_type}_temperature', '0.7')
        }
        cache_key = hashlib.md5(json.dumps(cache_data, sort_keys=True).encode()).hexdigest()
        cached_response = get_cache(cache_key)
        if cached_response:
            return cached_response
    
    retries = 0
    max_retries = config['API'].getint('max_retries', 3)
    while retries < max_retries:
        try:
            if model_type == 'openai':
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
                    "top_p": float(config['API'].get('openai_top_p', 1.0)),
                    "frequency_penalty": float(config['API'].get('openai_frequency_penalty', 0.0)),
                    "presence_penalty": float(config['API'].get('openai_presence_penalty', 0.0))
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
                            # 安全处理错误信息，不暴露完整消息
                            error_type = error_details['error'].get('type', 'unknown')
                            error_msg += f", 错误类型: {error_type}"
                    except:
                        # 不暴露响应内容，只提供一般性错误信息
                        pass
                    raise Exception(error_msg)
            
            elif model_type == 'claude':
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
                    # 安全处理错误信息
                    raise Exception(f"Claude API请求失败: 状态码 {response.status_code}")
            
            else:
                raise ValueError(f"不支持的模型类型: {model_type}")
            
            # 缓存结果
            if cache_enabled:
                set_cache(cache_key, result)
            return result
            
        except requests.exceptions.ConnectionError as e:
            if retries < max_retries - 1:
                logger.warning(f"连接错误 ({e})，{retry_delay}秒后重试 ({retries+1}/{max_retries})")
                time.sleep(retry_delay)
                retries += 1
            else:
                logger.error(f"连接失败，已达到最大重试次数: {e}")
                raise
        except requests.exceptions.Timeout as e:
            if retries < max_retries - 1:
                logger.warning(f"请求超时 ({e})，{retry_delay}秒后重试 ({retries+1}/{max_retries})")
                time.sleep(retry_delay)
                retries += 1
            else:
                logger.error(f"请求超时，已达到最大重试次数: {e}")
                raise
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
        
        # 验证输入参数
        allowed_dbms = ["mysql", "postgresql", "mssql", "oracle", "sqlite", "db2", "firebird", "sybase", "maxdb", "access"]
        allowed_vuln_types = ["union", "error", "boolean", "time", "stacked", "inline", "batch"]
        
        # 安全处理输入参数
        sanitized_dbms = next((db for db in allowed_dbms if db.lower() == dbms.lower()), "generic")
        sanitized_vuln_type = next((vt for vt in allowed_vuln_types if vt.lower() == vulnerability_type.lower()), "generic")
        
        prompt = f"""
为{sanitized_dbms}数据库生成一个针对{sanitized_vuln_type}漏洞的SQL注入payload。
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
        return fallback_payload(sanitized_dbms, sanitized_vuln_type)

def analyze_scan_results(results):
    try:
        # 确保results不为空
        if not results or not isinstance(results, str):
            return "无效的扫描结果"
            
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

def analyze_injection_results(injection_output, scan_info):
    """
    分析注入结果，提供详细的数据分析和建议
    """
    try:
        if not injection_output:
            return "无注入结果可分析"
            
        dbms = scan_info.get('dbms', 'unknown')
        
        # 处理长输出
        output_length = len(injection_output)
        max_analysis_length = 8000  # 估计值
        
        if output_length > max_analysis_length:
            logger.info(f"注入输出较长 ({output_length} 字符)，将进行分段分析")
            
            # 分段处理长文本
            segments = []
            segment_size = max_analysis_length - 500  # 留出空间给提示词
            
            # 分割文本
            for i in range(0, output_length, segment_size):
                segments.append(injection_output[i:i+segment_size])
            
            # 分析每个段落
            segment_results = []
            for i, segment in enumerate(segments):
                segment_prompt = f"""
分析以下sqlmap自动注入结果片段 ({i+1}/{len(segments)}):

数据库类型: {dbms}
注入结果片段:
{segment}

请提供这部分输出的关键发现:
"""
                segment_results.append(call_ai_model(segment_prompt))
            
            # 汇总分析
            summary_prompt = f"""
综合分析以下多个sqlmap注入结果片段的发现:

数据库类型: {dbms}
共{len(segments)}个片段的分析结果:

{''.join([f"片段{i+1}分析:\n{result}\n\n" for i, result in enumerate(segment_results)])}

请提供:
1. 提取数据的总体摘要和重要发现
2. 数据可能暴露的敏感信息
3. 基于这些数据的后续攻击可能性
4. 组织应该采取的防御措施
"""
            return call_ai_model(summary_prompt)
        else:
            # 原始处理逻辑
            prompt = f"""
分析以下sqlmap自动注入的结果，并提供关于提取的数据的见解:

数据库类型: {dbms}
注入结果:
{injection_output}

请提供:
1. 提取数据的摘要和重要发现
2. 数据可能暴露的敏感信息
3. 基于这些数据的后续攻击可能性
4. 组织应该采取的防御措施
"""
            return call_ai_model(prompt)
    except Exception as e:
        logger.warning(f"分析注入结果失败: {e}")
        return f"无法分析注入结果: {str(e)}"
