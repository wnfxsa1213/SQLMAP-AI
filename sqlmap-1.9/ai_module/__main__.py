import sys
import argparse
from .cli import main as start_cli
from .config import load_config, save_config, set_api_key, get_config_path
from .auto_inject import auto_inject

def main():
    parser = argparse.ArgumentParser(description="sqlmap AI模块命令行工具")
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # 配置命令
    config_parser = subparsers.add_parser("config", help="配置AI模块")
    config_parser.add_argument("--set-key", action="store_true", help="设置API密钥")
    config_parser.add_argument("--model", help="设置AI模型")
    config_parser.add_argument("--timeout", type=int, help="设置API超时时间(秒)")
    config_parser.add_argument("--show-key-location", action="store_true", help="显示API密钥存储位置")
    
    # CLI命令
    cli_parser = subparsers.add_parser("cli", help="启动交互式CLI")
    
    # 自动注入命令
    autoinject_parser = subparsers.add_parser("autoinject", help="自动扫描和注入")
    autoinject_parser.add_argument("url", help="目标URL")
    autoinject_parser.add_argument("--dump", action="store_true", help="提取数据")
    autoinject_parser.add_argument("--tables", help="指定要提取的表")
    autoinject_parser.add_argument("--verbose", action="store_true", help="详细输出")
    autoinject_parser.add_argument("--timeout", type=int, help="设置超时时间(秒)")
    
    # 解析参数
    args = parser.parse_args()
    
    if args.command == "config":
        config = load_config()
        
        if args.set_key:
            set_api_key()
        
        if args.model:
            config['API']['model'] = args.model
            print(f"AI模型已设置为: {args.model}")
        
        if args.timeout:
            config['API']['timeout'] = str(args.timeout)
            print(f"API超时时间已设置为: {args.timeout}秒")
        
        if args.show_key_location:
            config_path = get_config_path()
            print(f"API密钥存储位置: {config_path}")
        
        if args.model or args.timeout:
            save_config(config)
    
    elif args.command == "cli":
        start_cli()
    
    elif args.command == "autoinject":
        options = {}
        if args.dump:
            options["dump"] = True
        if args.tables:
            options["tables"] = args.tables
        if args.verbose:
            options["verbose"] = True
        if args.timeout:
            options["timeout"] = args.timeout
            
        results = auto_inject(args.url, options)
        if not results['success']:
            sys.exit(1)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
