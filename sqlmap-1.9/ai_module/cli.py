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
        
    def do_autoinject(self, arg):
        """自动扫描和注入
用法: autoinject <目标URL> [选项]
选项:
    --dump           提取数据
    --tables <表名>  指定要提取的表
    --verbose        详细输出
    --timeout <秒>   设置超时时间

示例: 
    autoinject http://example.com/vulnerable.php?id=1
    autoinject http://example.com/page.php?id=1 --dump --tables users
"""
        if not arg:
            print(_("请提供目标URL"))
            return
            
        args = arg.split()
        url = args[0]
        options = {}
        
        # 解析选项
        i = 1
        while i < len(args):
            if args[i] == "--dump":
                options["dump"] = True
            elif args[i] == "--tables" and i + 1 < len(args):
                options["tables"] = args[i + 1]
                i += 1
            elif args[i] == "--verbose":
                options["verbose"] = True
            elif args[i] == "--timeout" and i + 1 < len(args):
                try:
                    options["timeout"] = int(args[i + 1])
                    i += 1
                except ValueError:
                    print(_("错误: 超时值必须是整数"))
                    return
            else:
                print(_("未知选项: {}").format(args[i]))
                return
            i += 1
        
        print(_("[*] 开始自动SQL注入过程..."))
        print(_("[*] 目标URL: {}").format(url))
        
        results = auto_inject(url, options)
        
        if results['success']:
            print(_("[+] 自动注入过程成功完成"))
        else:
            print(_("[-] 自动注入过程未成功完成"))

    def do_exit(self, arg):
        """退出程序"""
        return True

    def do_quit(self, arg):
        """退出程序"""
        return True

def main():
    try:
        AICLI().cmdloop()
    except KeyboardInterrupt:
        print("\n再见！")
    except Exception as e:
        print(_("发生错误：{}").format(str(e)))

if __name__ == '__main__':
    main()
