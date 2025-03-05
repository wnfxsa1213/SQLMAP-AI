# SQLMap AI模块使用指南 (改进版)

## 概述

SQLMap AI模块是对SQLMap工具的增强，通过集成大型语言模型(LLM)赋予SQLMap更智能的能力。该模块提供：

1. **智能Payload生成**：根据目标数据库类型自动生成绕过WAF的注入payload
2. **扫描结果分析**：深入分析扫描结果，提供详细的漏洞解释
3. **漏洞解释**：详细说明发现的漏洞原理和潜在危害
4. **修复建议**：提供针对性的安全修复方案
5. **交互式CLI**：提供友好的命令行交互界面
6. **自动注入**：AI扫描后自动执行注入攻击并分析结果
7. **结构化解析**：强大的SQLMap输出解析器，支持多种输出格式

## 安装与配置

### 前提条件

- Python 3.7+
- SQLMap 1.9+
- 有效的API密钥
- 必需依赖：
  ```
  requests>=2.31.0
  keyring>=24.3.0
  python-dotenv>=1.0.0
  ```

### 安装依赖

可以使用以下命令安装所需依赖：

```bash
pip install -r requirements.txt
```

### API密钥管理 (安全性增强)

SQLMap AI模块提供两种推荐的安全API密钥管理方式：

1. **系统密钥环（推荐）**
   ```bash
   # 设置API密钥
   python -m ai_module config --set-key
   
   # 查看密钥存储位置
   python -m ai_module config --show-key-location
   
   # 移除密钥
   python -m ai_module config --remove-key
   ```

2. **环境变量**
   ```bash
   # Linux/macOS
   export SQLMAP_AI_KEY='your-api-key-here'
   
   # Windows
   set SQLMAP_AI_KEY=your-api-key-here
   ```

> **安全增强**: 配置文件中明文存储API密钥的选项已被移除。如果检测到配置文件中的API密钥，系统会自动将其迁移到系统密钥环中以提高安全性。

### 代理API配置 (增强版)

如果使用代理API服务，在`ai_config.ini`中配置：

```ini
[API]
openai_api_base = https://your-proxy-api.com/v1
openai_auth_type = bearer  # 可选: bearer, api_key
openai_auth_header = Authorization
openai_auth_prefix = Bearer
proxy = http://your-proxy-server:port  # 支持格式验证
```

## 使用方法

### 基础使用

1. **启动AI交互式命令行界面**
   ```bash
   python sqlmap.py --ai-cli
   ```
   这将启动一个交互式界面，您可以在其中：
   - 生成注入payload
   - 分析扫描结果
   - 获取漏洞解释
   - 获取修复建议

2. **智能注入测试**
   ```bash
   # 基本用法
   python sqlmap.py -u "http://example.com/page.php?id=1" --smart-payload
   
   # 指定数据库类型
   python sqlmap.py -u "http://example.com/vuln.php?id=1" --smart-payload --dbms=mysql
   
   # 结合其他SQLMap选项
   python sqlmap.py -u "http://example.com/vuln.php?id=1" --smart-payload --risk=3 --level=5
   ```

3. **扫描结果分析**
   ```bash
   # 实时分析
   python sqlmap.py -u "http://example.com/page.php?id=1" --ai-analysis
   
   # 分析并解释漏洞
   python sqlmap.py -u "http://example.com/page.php?id=1" --ai-analysis --explain-vuln
   
   # 完整分析（包含修复建议）
   python sqlmap.py -u "http://example.com/vuln.php?id=1" --ai-analysis --explain-vuln --suggest-fix
   ```

4. **批量测试**
   ```bash
   # 从文件读取目标
   python sqlmap.py -m targets.txt --smart-payload --ai-analysis
   
   # 从Burp日志分析
   python sqlmap.py -l burp.log --smart-payload --ai-analysis
   ```

5. **增强版自动注入** *(改进功能)*
   ```bash
   # 基本用法
   python -m ai_module autoinject "http://example.com/page.php?id=1"
   
   # 指定数据库类型
   python -m ai_module autoinject "http://example.com/page.php?id=1" --dbms mysql
   
   # 提取数据
   python -m ai_module autoinject "http://example.com/page.php?id=1" --dump
   
   # 自定义超时时间
   python -m ai_module autoinject "http://example.com/page.php?id=1" --timeout 600
   ```

### AI CLI模式详解

在AI CLI模式下（通过 `--ai-cli` 启动），提供以下详细命令：

1. **payload命令**：生成SQL注入payload
   ```bash
   # 基本语法
   payload <数据库类型> <注入类型> [选项]
   
   # 示例
   sqlmap-ai> payload mysql union         # 生成MySQL联合查询注入
   sqlmap-ai> payload postgresql time     # 生成PostgreSQL时间盲注
   sqlmap-ai> payload oracle boolean      # 生成Oracle布尔盲注
   sqlmap-ai> payload mysql union --waf   # 生成绕过WAF的payload
   ```

2. **analyze命令**：分析扫描结果
   ```bash
   # 基本语法
   analyze "<扫描结果描述>"
   
   # 示例
   sqlmap-ai> analyze "在id参数发现MySQL时间盲注，延迟5秒"
   sqlmap-ai> analyze "WAF拦截了UNION SELECT语句"
   sqlmap-ai> analyze "成功获取到数据库版本：MySQL 5.7.32"
   ```

3. **explain命令**：解释漏洞原理
   ```bash
   # 基本语法
   explain "<漏洞类型>"
   
   # 示例
   sqlmap-ai> explain "MySQL时间盲注"
   sqlmap-ai> explain "Oracle UNION查询注入"
   sqlmap-ai> explain "SQLite布尔盲注"
   ```

4. **fix命令**：提供修复建议
   ```bash
   # 基本语法
   fix "<漏洞描述>"
   
   # 示例
   sqlmap-ai> fix "MySQL联合查询注入漏洞"
   sqlmap-ai> fix "参数id存在时间盲注"
   sqlmap-ai> fix "存储过程注入漏洞"
   ```

5. **autoinject命令**：自动扫描和注入 *(增强功能)*
   ```bash
   # 基本语法
   autoinject <目标URL> [选项]
   
   # 选项
   --dbms <类型>     指定数据库类型（mysql, postgresql等）
   --dump           提取数据
   --tables <表名>   指定要提取的表
   --verbose        详细输出
   --timeout <秒>    设置超时时间
   --level <级别>    设置扫描级别 (1-5)
   --risk <风险>     设置风险级别 (1-3)
   --threads <数量>  设置线程数
   
   # 示例
   sqlmap-ai> autoinject http://example.com/vulnerable.php?id=1
   sqlmap-ai> autoinject http://example.com/page.php?id=1 --dbms mysql --dump
   sqlmap-ai> autoinject http://example.com/api.php?id=1 --dump --tables users
   sqlmap-ai> autoinject http://example.com/search.php?q=1 --verbose --timeout 300
   ```

6. **help命令**：获取帮助信息
   ```bash
   sqlmap-ai> help              # 显示所有命令
   sqlmap-ai> help payload      # 显示payload命令详细用法
   sqlmap-ai> help analyze      # 显示analyze命令详细用法
   ```

### 高级使用场景

1. **自定义注入场景**
   ```bash
   # 指定注入点
   python sqlmap.py -u "http://example.com/vuln.php?id=1" --smart-payload --param-mark="*"
   
   # 自定义HTTP头注入
   python sqlmap.py -u "http://example.com/api" --headers="X-Custom-Header: *" --smart-payload
   
   # JSON数据注入
   python sqlmap.py -u "http://example.com/api" --data='{"id": "*"}' --smart-payload
   ```

2. **与其他工具集成**
   ```bash
   # 结合Burp Suite
   python sqlmap.py -r request.txt --smart-payload --ai-analysis
   
   # 通过代理
   python sqlmap.py -u "http://example.com" --proxy="http://127.0.0.1:8080" --smart-payload
   ```

3. **自动化测试**
   ```bash
   # 批量目标扫描
   python sqlmap.py -m targets.txt --smart-payload --ai-analysis --batch
   
   # 定时任务
   python sqlmap.py -u "http://example.com" --smart-payload --ai-analysis --output-dir="daily_scan"
   
   # 增强版自动注入
   python -m ai_module autoinject "http://example.com/vuln.php?id=1" --dbms mysql --dump
   ```

4. **结果导出**
   ```bash
   # 导出AI分析报告
   python sqlmap.py -u "http://example.com" --ai-analysis --report-format=pdf
   
   # 导出建议修复方案
   python sqlmap.py -u "http://example.com" --suggest-fix --output-format=markdown
   ```

### 环境变量配置 (增强)

可以通过环境变量控制AI模块的行为：

```bash
# Windows
set SQLMAP_AI_DEBUG=1                # 启用调试模式
set SQLMAP_AI_CACHE_DIR=D:\cache     # 自定义缓存目录
set SQLMAP_AI_TIMEOUT=60             # 设置API超时时间（秒）
set SQLMAP_AI_CACHE_EXPIRY=14        # 设置缓存过期天数

# Linux/macOS
export SQLMAP_AI_DEBUG=1
export SQLMAP_AI_CACHE_DIR=/tmp/cache
export SQLMAP_AI_TIMEOUT=60
export SQLMAP_AI_CACHE_EXPIRY=14
```

## 最佳实践

1. **API密钥管理** *(安全性增强)*
   - 使用系统密钥环存储API密钥
   - 定期轮换API密钥
   - 避免在代码或配置文件中硬编码密钥
   - 使用配置验证功能确保设置正确

2. **性能优化** *(性能增强)*
   - 启用改进的缓存机制减少API调用
   - 根据操作类型使用合适的超时配置
   - 使用缓存统计功能监控资源使用
   - 定期清理过期缓存释放空间

3. **自定义配置**
   - 利用TIMEOUTS部分配置不同操作的超时时间
   - 自定义提示词模板
   - 配置代理服务器

4. **自动注入优化** *(改进功能)*
   - 使用增强版自动注入提高成功率
   - 明确指定数据库类型加快扫描速度
   - 使用结构化解析获取更准确的结果

## 新增功能与改进

### 1. 安全性增强
- **安全API密钥管理**：移除配置文件中明文存储API密钥的选项，自动迁移到系统密钥环
- **输入验证**：增加数据库类型和漏洞类型等用户输入的验证，防止提示注入攻击
- **代理验证**：添加代理URL格式验证，避免不安全的代理配置
- **敏感信息保护**：优化错误处理，不再在错误信息中暴露敏感API响应

### 2. 缓存系统改进
- **增强的缓存键**：缓存键现在包含模型和温度等参数，确保不同请求参数不会冲突
- **缓存统计**：新增缓存统计功能，显示文件数量、大小和过期情况
- **自动清理**：自动检测和删除过期缓存，优化磁盘空间
- **可配置缓存目录**：支持通过配置或环境变量自定义缓存位置

### 3. SQLMap输出解析器
- **结构化解析**：新的SQLMapOutputParser类提供更准确的SQLMap输出解析
- **多格式支持**：支持解析不同版本和格式的SQLMap输出
- **数据提取**：能够从扫描结果中提取数据库、表和数据记录信息
- **鲁棒性增强**：针对不同输出格式的适应性和错误恢复能力增强

### 4. 超时与配置管理
- **操作类型超时**：不同操作类型（短扫描、数据提取等）使用不同超时设置
- **配置验证**：新增配置验证功能，检查并报告配置问题
- **类型转换与验证**：自动处理配置项类型转换和验证
- **默认值备份**：配置加载失败时自动回退到默认配置

## 故障排除

**Q: API调用失败怎么办？**

A: 检查以下几点：
- 确认API密钥是否正确
- 使用`python -m ai_module config --validate`验证配置
- 检查网络连接是否正常
- 查看是否超出API调用限制
- 检查代理配置是否正确

**Q: 智能分析结果不准确？**

A: 可以尝试以下解决方案：
- 提供更详细的目标信息（如明确指定DBMS类型）
- 调整模型参数（如增加温度、最大令牌数等）
- 更新至最新版本的AI模块

**Q: 缓存不工作？** *(增强)*

A: 可能的原因：
- 缓存目录权限问题
- 缓存配置未正确启用
- 缓存过期时间设置过短

解决方法：
```bash
# 检查缓存目录和状态
python -m ai_module cache --status

# 清理缓存
python -m ai_module cache --clear

# 重建缓存
python -m ai_module cache --rebuild

# 验证缓存设置
python -m ai_module config --validate
```

**Q: 自动注入失败？** *(增强功能)*

A: 可能的原因：
- URL格式不正确
- 目标网站无漏洞或有WAF保护
- 参数名称不匹配
- 数据库类型指定错误
- SQLMap输出格式变化导致解析失败

解决方法：
```bash
# 尝试指定正确的数据库类型
python -m ai_module autoinject "http://example.com/page.php?id=1" --dbms mysql

# 使用更基本的命令减少复杂性
python -m ai_module autoinject "http://example.com/page.php?id=1" --batch

# 查看详细输出进行调试
python -m ai_module autoinject "http://example.com/page.php?id=1" --verbose

# 尝试使用更高级别的扫描
python -m ai_module autoinject "http://example.com/page.php?id=1" --level 5 --risk 3
```

**Q: 如何处理SQLMap输出解析错误？** *(新增)*

A: 如果解析器无法正确解析SQLMap输出：
1. 使用`--verbose`选项获取详细输出
2. 检查SQLMap版本是否兼容（推荐1.9+）
3. 尝试更新到最新版本的AI模块
4. 手动检查SQLMap输出格式是否与预期一致

**Q: 如何设置自定义超时时间？** *(新增)*

A: 可以通过以下方式设置超时：
1. 在配置文件中的TIMEOUTS部分设置:
   ```ini
   [TIMEOUTS]
   api_call_timeout = 30
   command_execution_timeout = 300
   command_execution_long_timeout = 900
   ```
2. 通过命令行参数:
   ```bash
   python -m ai_module autoinject "http://example.com/page.php?id=1" --timeout 600
   ```
3. 通过环境变量:
   ```bash
   export SQLMAP_AI_TIMEOUT=60
   ```

## 版本历史与更新

### v1.0.0 (初始版本)
- 基础AI分析功能
- 智能payload生成
- 漏洞解释与修复建议

### v1.1.0
- 添加国际化支持
- 改进缓存机制
- 优化API调用效率

### v1.2.0
- 添加更多数据库类型支持
- 改进WAF绕过能力
- 增加批量扫描功能

### v1.3.0
- 添加AI扫描后自动注入功能
- 增强注入结果分析能力
- 优化交互式CLI界面

### v1.4.0 
- 添加简化版自动注入功能，提高稳定性
- 修复参数处理问题
- 优化错误处理和调试信息
- 添加更多使用案例和故障排除指南

### v1.5.0 (最新版本)
- **安全性增强**：改进API密钥管理，防止提示注入
- **性能优化**：增强缓存系统，配置超时设置
- **解析改进**：新增SQLMapOutputParser结构化解析器
- **配置增强**：添加配置验证，改进类型处理
- **异常处理**：更精细的异常处理和错误恢复
- 修复了多个BUG和稳定性问题

## 贡献与反馈

欢迎提交问题报告、功能请求或贡献代码：

1. 在GitHub上提交Issue
2. 提交Pull Request
3. 发送反馈至维护者邮箱

## 许可证

SQLMap AI模块遵循与SQLMap相同的许可证，详见项目根目录的LICENSE文件。
