import sys
import argparse
from .cli import main as start_cli
from .config import load_config, save_config, set_api_key, get_config_path
from .auto_inject import auto_inject

def main():
    """AI模块的主入口点"""
    parser = argparse.ArgumentParser(description="SQLMap AI模块")
    
    # 添加子命令
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # CLI命令
    cli_parser = subparsers.add_parser("cli", help="启动交互式CLI")
    
    # 配置命令
    config_parser = subparsers.add_parser("config", help="配置AI模块")
    config_parser.add_argument("--set-key", action="store_true", help="设置API密钥")
    config_parser.add_argument("--show-key-location", action="store_true", help="显示API密钥存储位置")
    config_parser.add_argument("--remove-key", action="store_true", help="移除API密钥")
    config_parser.add_argument("--validate", action="store_true", help="验证配置")
    
    # 缓存命令
    cache_parser = subparsers.add_parser("cache", help="管理缓存")
    cache_parser.add_argument("--clear", action="store_true", help="清除缓存")
    cache_parser.add_argument("--status", action="store_true", help="显示缓存状态")
    cache_parser.add_argument("--rebuild", action="store_true", help="重建缓存")
    
    # 生成payload命令
    payload_parser = subparsers.add_parser("payload", help="生成SQL注入payload")
    payload_parser.add_argument("dbms", help="数据库类型 (mysql, postgresql, oracle, etc.)")
    payload_parser.add_argument("type", help="注入类型 (union, error, boolean, time, etc.)")
    payload_parser.add_argument("--waf", action="store_true", help="生成绕过WAF的payload")
    payload_parser.add_argument("--level", type=int, choices=range(1, 6), default=3, help="复杂度级别 (1-5)")
    
    # 分析命令
    analyze_parser = subparsers.add_parser("analyze", help="分析扫描结果")
    analyze_parser.add_argument("result", help="扫描结果描述或文件路径")
    analyze_parser.add_argument("--file", action="store_true", help="从文件读取结果")
    analyze_parser.add_argument("--explain", action="store_true", help="解释漏洞")
    analyze_parser.add_argument("--suggest-fix", action="store_true", help="提供修复建议")
    
    args = parser.parse_args()
    
    # 处理命令
    if args.command == "cli":
        from ai_module.cli import start_cli
        start_cli()
    elif args.command == "config":
        from ai_module.config import handle_config_command
        handle_config_command(args)
    elif args.command == "cache":
        from ai_module.cache import handle_cache_command
        handle_cache_command(args)
    elif args.command == "payload":
        from ai_module.core import AICore
        ai = AICore()
        try:
            payload = ai.generate_smart_payload(args.dbms, args.type, waf=args.waf, level=args.level)
            print(f"生成的payload: {payload}")
        except Exception as e:
            print(f"生成payload失败: {e}")
    elif args.command == "analyze":
        from ai_module.core import AICore
        ai = AICore()
        try:
            if args.file:
                with open(args.result, 'r') as f:
                    result = f.read()
            else:
                result = args.result
                
            analysis = ai.analyze_scan_results(result)
            print("分析结果:")
            print(analysis)
            
            if args.explain:
                explanation = ai.explain_vulnerability(result)
                print("\n漏洞解释:")
                print(explanation)
                
            if args.suggest_fix:
                fixes = ai.suggest_fix(result)
                print("\n修复建议:")
                print(fixes)
        except Exception as e:
            print(f"分析失败: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
