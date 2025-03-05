import sys
import argparse
from .cli import start_cli
from .config import load_config, save_config, set_api_key

def main():
    parser = argparse.ArgumentParser(description="sqlmap AI模块命令行工具")
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # 配置命令
    config_parser = subparsers.add_parser("config", help="配置AI模块")
    config_parser.add_argument("--set-key", action="store_true", help="设置API密钥")
    config_parser.add_argument("--model", help="设置AI模型")
    config_parser.add_argument("--timeout", type=int, help="设置API超时时间(秒)")
    
    # CLI命令
    cli_parser = subparsers.add_parser("cli", help="启动交互式CLI")
    
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
        
        if args.model or args.timeout:
            save_config(config)
    
    elif args.command == "cli":
        start_cli()
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
