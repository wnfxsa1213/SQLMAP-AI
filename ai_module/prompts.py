PROMPT_TEMPLATES = {
    "payload_generation": """
    作为SQL注入专家，为{dbms}数据库生成一个针对{vulnerability_type}漏洞的SQL注入payload。
    要求:
    1. 高效且难以被WAF检测
    2. 解释payload的工作原理
    3. 提供可能的变体
    """,
    
    "vulnerability_explanation": """
    详细解释{dbms}数据库中的{vulnerability_type}类型SQL注入漏洞:
    1. 漏洞原理和技术细节
    2. 攻击者可能的利用方式
    3. 对系统的潜在影响
    4. 修复建议和最佳实践
    5. 相关的CVE或已知案例
    """,
    
    "result_analysis": """
    分析以下sqlmap扫描结果:
    {results}
    
    请提供:
    1. 发现漏洞的严重性评估
    2. 可能的影响范围
    3. 推荐的修复步骤
    4. 额外的安全建议
    """
}

def get_prompt(template_name, **kwargs):
    """获取并格式化提示词模板"""
    if template_name not in PROMPT_TEMPLATES:
        raise ValueError(f"未知的提示词模板: {template_name}")
    
    template = PROMPT_TEMPLATES[template_name]
    return template.format(**kwargs)
