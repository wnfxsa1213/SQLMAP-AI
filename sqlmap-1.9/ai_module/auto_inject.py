import os
import re
import subprocess
import sys
import tempfile
import json
from .config import load_config, get_api_key
from .ai_integration import call_ai_model, generate_smart_payload, analyze_injection_results
from .i18n import _
from pathlib import Path

def parse_scan_results(scan_output):
    """
    解析sqlmap扫描输出，提取注入点和数据库类型信息
    """
    injection_points = []
    
    # 更改正则表达式以更好地匹配sqlmap的输出格式
    # 尝试多种可能的注入点输出格式
    patterns = [
        # 标准格式
        r"Parameter:\s*'([^']+)'.*?Type:\s*([^(]+).*?Title:\s*([^\n]+)",
        # 简化格式
        r"parameter\s*'([^']+)'\s*is\s*([^(]+)",
        # AI分析结果格式
        r"注入点是\s*([^\s,]+).*?数据库类型是\s*([^\s,]+)"
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, scan_output, re.DOTALL | re.IGNORECASE)
        for match in matches:
            if len(match.groups()) >= 2:
                param = match.group(1)
                if len(match.groups()) >= 3:
                    vuln_type = match.group(2).strip()
                    title = match.group(3).strip()
                else:
                    vuln_type = match.group(2).strip() if len(match.groups()) > 1 else "unknown"
                    title = "SQL注入漏洞"
                
                injection_points.append({
                    'parameter': param,
                    'type': vuln_type,
                    'title': title
                })
    
    # 查找数据库类型 - 增加更多匹配模式
    dbms_patterns = [
        r"back-end DBMS:\s*([^\n]+)",
        r"数据库类型是\s*([^\s,]+)",
        r"DBMS\s*=\s*([^\s]+)"
    ]
    
    dbms = "unknown"
    for pattern in dbms_patterns:
        dbms_match = re.search(pattern, scan_output, re.IGNORECASE)
        if dbms_match:
            dbms = dbms_match.group(1).strip()
            break
    
    # 如果没有发现注入点，但输出中提到了SQL注入漏洞，尝试解析简单信息
    if not injection_points and "sql injection" in scan_output.lower() or "注入漏洞" in scan_output:
        param_match = re.search(r"parameter[:\s]*'([^']+)'", scan_output, re.IGNORECASE)
        id_match = re.search(r"(\bid\b|\bparam\b)[\s:]*([^\s,]+)", scan_output, re.IGNORECASE)
        
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
    
    return {
        'injection_points': injection_points,
        'dbms': dbms
    }

def analyze_vulnerability(scan_info):
    """
    分析漏洞，使用AI生成攻击策略
    """
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
        prompt += f"{i}. 参数: {point['parameter']}, 类型: {point['type']}, 描述: {point['title']}\n"
    
    prompt += """
请提供:
1. 每个注入点的最优攻击方式
2. 推荐的payload
3. 预期的数据提取方法
4. 攻击的风险评估
"""
    
    try:
        result = call_ai_model(prompt)
        return result
    except Exception as e:
        return f"AI分析失败: {str(e)}"

def generate_inject_command(url, scan_info, options=None):
    """
    根据扫描信息生成注入命令
    """
    if not scan_info['injection_points']:
        return None
    
    # 使用第一个注入点生成命令
    point = scan_info['injection_points'][0]
    dbms = scan_info['dbms']
    
    # 确保参数名称格式正确
    param = point['parameter']
    # 删除可能的额外文本，保留纯参数名
    param = re.sub(r"[，,:\s]+.*$", "", param)
    param = param.strip()
    
    # 基本的sqlmap命令
    cmd = ["python", "sqlmap.py", "-u", url]
    
    # 添加参数信息
    cmd.extend(["-p", param])
    
    # 添加数据库类型
    if dbms and dbms.lower() != "unknown":
        # 清理数据库类型字符串，只保留有效的数据库名称
        cleaned_dbms = re.sub(r"[^a-zA-Z0-9]+", "", dbms.split()[0])
        cmd.extend(["--dbms", cleaned_dbms])
    
    # 添加更多有用的扫描选项
    cmd.extend(["--level", "3"])
    cmd.extend(["--risk", "2"])
    
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
    """
    执行自动扫描和注入过程
    """
    if options is None:
        options = {}
    
    results = {
        'scan_output': '',
        'analysis': '',
        'injection_output': '',
        'success': False
    }
    
    # 步骤1: 进行扫描
    print(_("[*] 开始扫描目标URL以寻找SQL注入漏洞..."))
    
    # 使用更完整的扫描参数，以提高识别率
    scan_cmd = [
        "python", "sqlmap.py", 
        "-u", url, 
        "--batch",
        "--level", "3",
        "--risk", "3",  # 提高到更高的风险级别
        "--technique", "BEUSTQ",  # 使用所有技术
        "--time-sec", "10",  # 设置时间延迟
        "--threads", "3",  # 使用多线程
        "--smart"  # 智能模式
    ]
    
    # 如果提供了数据库类型，则添加该参数
    if "dbms" in options:
        scan_cmd.extend(["--dbms", options["dbms"]])
    
    # 设置超时选项
    if "timeout" in options:
        scan_cmd.extend(["--timeout", str(options["timeout"])])
    
    # 是否包含详细输出
    if options.get("verbose", False):
        scan_cmd.append("-v")
    
    try:
        print(_("[*] 执行命令: {}").format(" ".join(scan_cmd)))
        
        # 首先进行快速检查，看看是否有AI分析结果可以使用
        quick_check_cmd = [
            "python", "sqlmap.py", 
            "-u", url, 
            "--batch",
            "--ai-analysis",  # 使用AI分析
            "--dbms", options.get("dbms", "mysql"),  # 默认使用MySQL
        ]
        
        print(_("[*] 正在进行AI预分析..."))
        pre_check = subprocess.Popen(
            quick_check_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        pre_check_output, pre_check_error = pre_check.communicate()
        
        # 检查AI分析结果
        if "发现了SQL注入漏洞" in pre_check_output or "AI分析结果" in pre_check_output:
            print(_("[+] AI预分析检测到漏洞"))
            # 添加这个信息到结果中
            results['pre_analysis'] = pre_check_output
            
            # 最基本的注入命令
            basic_cmd = [
                "python", "sqlmap.py", 
                "-u", url, 
                "--batch",
                "--dbms", options.get("dbms", "mysql")
            ]
            
            # 添加数据提取选项
            if options.get("dump", False):
                basic_cmd.append("--dump")
            
            # 添加指定表的选项
            if "tables" in options:
                basic_cmd.extend(["--tables", options["tables"]])
            
            print(_("[*] 开始执行自动注入..."))
            print(_("[*] 执行命令: {}").format(" ".join(basic_cmd)))
            
            inject_process = subprocess.Popen(
                basic_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            inject_output, inject_error = inject_process.communicate()
            results['injection_output'] = inject_output
            
            if inject_process.returncode != 0:
                print(_("[-] 注入执行失败"))
                if inject_error:
                    print(f"错误信息: {inject_error[:200]}")
            else:
                print(_("[+] 自动注入完成"))
                results['success'] = True
            
            return results
        
        # 如果AI预分析未发现漏洞，返回简单结果
        print(_("[-] AI预分析未发现SQL注入漏洞"))
        results['analysis'] = "AI预分析未发现SQL注入漏洞"
        return results
    
    except Exception as e:
        print(_("[-] 自动注入过程中发生错误: {}").format(str(e)))
        results['analysis'] = f"错误: {str(e)}"
        return results 