import cmd
import sys
from typing import Optional
from .config import get_api_key, load_config
from .ai_integration import call_ai_model
from .auto_inject import auto_inject
from .i18n import _

class AICLI(cmd.Cmd):
    intro = _("""欢迎使用SQLMap AI交互式命令行界面！
输入 'help' 或 '?' 查看可用命令。
输入 'exit' 或 'quit' 退出。""")
    prompt = 'sqlmap-ai> '

    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.api_key = get_api_key()
        if not self.api_key:
            print(_("错误：未找到API密钥。请先设置API密钥。"))
            sys.exit(1)

    def do_payload(self, arg):
        """生成SQL注入payload
用法: payload <数据库类型> <注入类型>
示例: payload mysql union"""
        if not arg:
            print(_("请指定数据库类型和注入类型"))
            return
        
        args = arg.split()
        if len(args) < 2:
            print(_("用法: payload <数据库类型> <注入类型>"))
            return
        
        dbms, vuln_type = args[0], args[1]
        prompt = f"为{dbms}数据库生成一个{vuln_type}类型的SQL注入payload"
        
        response = call_ai_model(
            prompt=prompt,
            model_override=None,  # 使用默认模型
            api_key=self.api_key,
            config=self.config
        )
        print(response)

    def do_analyze(self, arg):
        """分析扫描结果
用法: analyze <扫描结果>
示例: analyze "发现MySQL注入点：id参数" """
        if not arg:
            print(_("请提供要分析的扫描结果"))
            return
        
        prompt = f"分析以下SQL注入扫描结果并提供详细解释：{arg}"
        response = call_ai_model(prompt, self.api_key, self.config)
        print(response)

    def do_explain(self, arg):
        """解释漏洞
用法: explain <漏洞描述>
示例: explain "MySQL时间盲注" """
        if not arg:
            print(_("请提供要解释的漏洞描述"))
            return
        
        prompt = f"详细解释以下SQL注入漏洞的原理和危害：{arg}"
        response = call_ai_model(prompt, self.api_key, self.config)
        print(response)

    def do_fix(self, arg):
        """提供修复建议
用法: fix <漏洞描述>
示例: fix "MySQL联合查询注入" """
        if not arg:
            print(_("请提供需要修复建议的漏洞描述"))
            return
        
        prompt = f"为以下SQL注入漏洞提供具体的修复建议和最佳实践：{arg}"
        response = call_ai_model(prompt, self.api_key, self.config)
        print(response)
        
    def do_exit(self, arg):
        """退出程序"""
        return True

    def do_quit(self, arg):
        """退出程序"""
        return True

def start_cli():
    """启动交互式CLI"""
    print("SQLMap AI CLI - 输入'help'获取帮助，'exit'退出")
    
    ai = AICLI()
    
    while True:
        try:
            cmd = input("sqlmap-ai> ").strip()
            
            if not cmd:
                continue
                
            if cmd.lower() in ['exit', 'quit', 'q']:
                break
                
            parts = cmd.split()
            command = parts[0].lower()
            
            if command == 'help':
                if len(parts) > 1:
                    show_command_help(parts[1])
                else:
                    show_help()
                    
            elif command == 'payload':
                if len(parts) < 3:
                    print("错误: 需要指定数据库类型和注入类型")
                    print("用法: payload <数据库类型> <注入类型> [--waf]")
                    continue
                    
                dbms = parts[1]
                injection_type = parts[2]
                waf = '--waf' in parts
                
                try:
                    payload = ai.do_payload(f"{dbms} {injection_type} {'--waf' if waf else ''}")
                    print(f"生成的payload: {payload}")
                except Exception as e:
                    print(f"生成payload失败: {e}")
                    
            elif command == 'analyze':
                if len(parts) < 2:
                    print("错误: 需要提供扫描结果描述")
                    print("用法: analyze \"<扫描结果描述>\"")
                    continue
                    
                # 重新组合引号内的内容
                result_text = ' '.join(parts[1:])
                if result_text.startswith('"') and result_text.endswith('"'):
                    result_text = result_text[1:-1]
                    
                try:
                    analysis = ai.do_analyze(result_text)
                    print("分析结果:")
                    print(analysis)
                except Exception as e:
                    print(f"分析失败: {e}")
                    
            elif command == 'explain':
                if len(parts) < 2:
                    print("错误: 需要提供漏洞类型")
                    print("用法: explain \"<漏洞类型>\"")
                    continue
                    
                # 重新组合引号内的内容
                vuln_text = ' '.join(parts[1:])
                if vuln_text.startswith('"') and vuln_text.endswith('"'):
                    vuln_text = vuln_text[1:-1]
                    
                try:
                    explanation = ai.do_explain(vuln_text)
                    print("漏洞解释:")
                    print(explanation)
                except Exception as e:
                    print(f"解释失败: {e}")
                    
            elif command == 'fix':
                if len(parts) < 2:
                    print("错误: 需要提供漏洞描述")
                    print("用法: fix \"<漏洞描述>\"")
                    continue
                    
                # 重新组合引号内的内容
                vuln_text = ' '.join(parts[1:])
                if vuln_text.startswith('"') and vuln_text.endswith('"'):
                    vuln_text = vuln_text[1:-1]
                    
                try:
                    fixes = ai.do_fix(vuln_text)
                    print("修复建议:")
                    print(fixes)
                except Exception as e:
                    print(f"生成修复建议失败: {e}")
                    
            else:
                print(f"未知命令: {command}")
                print("输入'help'获取可用命令列表")
                
        except KeyboardInterrupt:
            print("\n退出中...")
            break
            
        except Exception as e:
            print(f"错误: {e}")
            
    print("再见!")

def show_help():
    """显示帮助信息"""
    print("可用命令:")
    print("  payload <数据库类型> <注入类型> [--waf] - 生成SQL注入payload")
    print("  analyze \"<扫描结果描述>\" - 分析扫描结果")
    print("  explain \"<漏洞类型>\" - 解释漏洞原理")
    print("  fix \"<漏洞描述>\" - 提供修复建议")
    print("  help [命令] - 显示帮助信息")
    print("  exit - 退出CLI")

def show_command_help(command):
    """显示特定命令的帮助信息"""
    if command == 'payload':
        print("payload - 生成SQL注入payload")
        print("用法: payload <数据库类型> <注入类型> [--waf]")
        print("参数:")
        print("  数据库类型 - 目标数据库类型 (mysql, postgresql, oracle, etc.)")
        print("  注入类型 - 注入技术 (union, error, boolean, time, etc.)")
        print("  --waf - 生成绕过WAF的payload")
        print("示例:")
        print("  payload mysql union")
        print("  payload postgresql time --waf")
        
    elif command == 'analyze':
        print("analyze - 分析扫描结果")
        print("用法: analyze \"<扫描结果描述>\"")
        print("参数:")
        print("  扫描结果描述 - SQLMap扫描结果的描述或摘要")
        print("示例:")
        print("  analyze \"在id参数发现MySQL时间盲注，延迟5秒\"")
        
    elif command == 'explain':
        print("explain - 解释漏洞原理")
        print("用法: explain \"<漏洞类型>\"")
        print("参数:")
        print("  漏洞类型 - SQL注入漏洞的类型")
        print("示例:")
        print("  explain \"MySQL时间盲注\"")
        print("  explain \"Oracle UNION查询注入\"")
        
    elif command == 'fix':
        print("fix - 提供修复建议")
        print("用法: fix \"<漏洞描述>\"")
        print("参数:")
        print("  漏洞描述 - SQL注入漏洞的描述")
        print("示例:")
        print("  fix \"MySQL联合查询注入漏洞\"")
        print("  fix \"参数id存在时间盲注\"")
        
    elif command == 'help':
        print("help - 显示帮助信息")
        print("用法: help [命令]")
        print("参数:")
        print("  命令 - 可选，要显示帮助的特定命令")
        
    elif command == 'exit':
        print("exit - 退出CLI")
        print("别名: quit, q")
        
    else:
        print(f"未知命令: {command}")
        print("输入'help'获取可用命令列表")

def main():
    try:
        start_cli()
    except KeyboardInterrupt:
        print("\n再见！")
    except Exception as e:
        print(_("发生错误：{}").format(str(e)))

if __name__ == '__main__':
    main()
