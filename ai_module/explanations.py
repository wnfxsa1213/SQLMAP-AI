from .ai_integration import call_ai_model

def explain_vulnerability(vuln_type, dbms):
    prompt = f"""
    详细解释{dbms}数据库中的{vuln_type}类型SQL注入漏洞:
    1. 漏洞原理
    2. 攻击者可能的利用方式
    3. 对系统的潜在影响
    4. 修复建议和最佳实践
    """
    return call_ai_model(prompt)

def suggest_fixes(vuln_type, dbms, code_sample):
    prompt = f"""
    针对以下{dbms}数据库代码中的{vuln_type}类型SQL注入漏洞,提供修复建议:
    
    {code_sample}
    
    请提供:
    1. 安全的替代代码
    2. 修复说明
    3. 额外的防护措施
    """
    return call_ai_model(prompt)
