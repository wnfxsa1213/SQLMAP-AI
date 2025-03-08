# SQLMap AI模块使用指南 (改进版)

## 最近更新

**2024年3月8日更新**：
- **修复了扫描功能**：修复了AI模块与原始SQLMap扫描功能的集成问题，现在可以正常执行SQL注入扫描并进行AI分析
- **改进了结果分析**：增强了AI分析功能，可以更准确地解析SQLMap扫描结果
- **优化了错误处理**：添加了更健壮的错误处理机制，当AI功能失败时会自动回退到标准SQLMap功能

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
   python sqlmap.py -u "http://124.70.71.251:40797/new_list.php?id=1" --smart-payload
   
   # 指定数据库类型
   python sqlmap.py -u "http://example.com/vuln.php?id=1" --smart-payload --dbms=mysql
   
   # 结合其他SQLMap选项
   python sqlmap.py -u "http://example.com/vuln.php?id=1" --smart-payload --risk=3 --level=5
   ```

3. **扫描结果分析**
   ```bash
   # 实时分析
   python sqlmap.py -u "http://www.sztest.net.cn/about.php?ID=1" --ai-analysis
   
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
   
   # 示例输出
   [*] 开始扫描目标URL以寻找SQL注入漏洞...
   [*] 执行命令: python sqlmap.py -u http://example.com/page.php?id=1 --batch --level 3 --risk 2 --technique BEUSTQ --threads 3 --smart
   [+] 发现 1 个SQL注入点
   [*] 分析注入点: id参数存在MySQL布尔型盲注
   [+] 成功获取数据库版本: MySQL 5.7.32
   
   # 指定数据库类型
   python -m ai_module autoinject "http://example.com/page.php?id=1" --dbms mysql
   
   # 提取数据
   python -m ai_module autoinject "http://example.com/page.php?id=1" --dump
   
   # 自定义超时时间
   python -m ai_module autoinject "http://example.com/page.php?id=1" --timeout 600
   ```

   > **注意**: 如果遇到 `注入执行失败，返回码: 1` 错误，请检查以下几点：
   > - 确保SQLMap路径配置正确
   > - 检查目标URL是否可访问
   > - 尝试手动运行SQLMap命令进行测试
   > - 使用v1.2.0或更高版本，该版本修复了start()函数的相关问题

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

### 常见问题及解决方案

1. **AI分析未显示结果但SQLMap检测到漏洞**
   - **问题**：SQLMap成功检测到SQL注入漏洞，但AI分析显示"未发现漏洞"
   - **解决方案**：
     - 确保使用最新版本的AI模块
     - 尝试增加扫描的详细程度：`python sqlmap.py -u "目标URL" --ai-analysis -v 3`
     - 检查API密钥是否有效并且有足够的配额

2. **API连接错误**
   - **问题**：出现"无法连接到API服务"或类似错误
   - **解决方案**：
     - 检查网络连接
     - 验证API配置是否正确
     - 如果使用代理，确保代理服务器可访问
     - 尝试使用`--api-timeout`参数增加超时时间

3. **内存错误**
   - **问题**：在处理大型扫描结果时出现内存错误
   - **解决方案**：
     - 减少扫描范围或分批次进行扫描
     - 使用`--output-dir`参数将结果保存到磁盘
     - 增加系统可用内存或使用虚拟内存

4. **命令行参数冲突**
   - **问题**：某些AI模块参数与原始SQLMap参数冲突
   - **解决方案**：
     - 查阅文档确认参数兼容性
     - 尝试使用AI CLI模式单独执行AI相关操作
     - 使用`--ai-config`参数指定单独的配置文件

5. **扫描结果不完整**
   - **问题**：AI分析结果不完整或缺少关键信息
   - **解决方案**：
     - 增加扫描的详细程度：`-v 3`或更高
     - 使用`--explain-vuln --suggest-fix`获取更详细的分析
     - 手动检查SQLMap日志文件获取完整信息

6. **自动注入失败（返回码1）**
   - **问题**：执行`python -m ai_module autoinject`命令时出现"注入执行失败，返回码: 1"错误
   - **错误示例**：
     ```
     [*] 开始扫描目标URL以寻找SQL注入漏洞...
     [*] 执行命令: python sqlmap.py -u http://example.com/page.php?id=1 --batch --level 3 --risk 2 --technique BEUSTQ --threads 3 --smart
     [+] 发现 1 个SQL注入点
     [*] 执行注入命令: python sqlmap.py -u http://example.com/page.php?id=1 -p id --dbms mysql --level 3 --risk 2
     [-] 注入执行失败，返回码: 1
     错误信息: Traceback (most recent call last):
       File "path/to/sqlmap.py", line 219, in main
         start()
       File "path/to/sqlmap.py", line 270, in start
     ```
   - **解决方案**：
     - 升级到v1.2.0或更高版本，该版本修复了start()函数的相关问题
     - 检查SQLMap安装路径是否正确配置
     - 尝试手动运行错误信息中显示的SQLMap命令进行测试
     - 检查目标URL是否可访问，或者WAF是否阻止了连接
     - 在命令中添加`--verbose`参数获取更详细的错误信息：`python -m ai_module autoinject "URL" --verbose`
     - **新增解决方法**：使用最新版本的auto_inject.py，它添加了多种备选执行方式，包括：
       - 直接使用SQLMap API进行注入
       - 使用简化的命令行参数
       - 自动添加--batch参数确保无交互
       - 智能检测SQLMap路径

### 调试模式

启用调试模式获取更详细的错误信息：

```bash
# 启用调试模式
python sqlmap.py -u "http://example.com/page.php?id=1" --ai-analysis --debug

# 将调试信息保存到文件
python sqlmap.py -u "http://example.com/page.php?id=1" --ai-analysis --debug --debug-file=debug.log
```

### 获取支持

如果遇到无法解决的问题，请通过以下方式获取支持：

1. 提交GitHub Issue：附上详细的错误信息和复现步骤
2. 查阅官方文档：[SQLMap AI模块文档](https://github.com/your-repo/sqlmap-ai)
3. 加入社区讨论：[SQLMap论坛](https://github.com/sqlmapproject/sqlmap/discussions)

## 版本历史与更新

### v1.2.0 (2024年3月8日)

- **主要更新**：
  - 修复了AI模块与原始SQLMap扫描功能的集成问题
  - 改进了扫描结果分析功能，现在可以正确识别SQLMap检测到的漏洞
  - 增强了错误处理机制，当AI功能失败时会自动回退到标准SQLMap功能
  - 优化了结果解析逻辑，提高了分析准确性
  - **增强自动注入功能**：
    - 添加了多种执行方式，提高成功率
    - 智能检测SQLMap路径
    - 直接调用SQLMap API作为首选方式
    - 使用简化命令作为备选方案

- **技术改进**：
  - 重构了`start()`函数，确保正确调用原始SQLMap的扫描功能
    - 修复了自动注入时出现的"返回码1"错误
    - 改进了参数传递机制，确保命令行参数正确传递给SQLMap核心
    - 添加了更详细的错误日志记录
  - 添加了对`kb.results`的空值检查，防止分析过程中出现错误
  - 改进了AI分析结果的格式化输出
  - 增加了详细的日志记录，便于调试和问题排查
  - 增强了auto_inject.py模块：
    - 添加了SQLMap路径智能检测
    - 实现了多种执行方式的自动切换
    - 改进了错误处理和恢复机制

### v1.1.0 (2024年2月15日)

- **功能增强**：
  - 添加了系统密钥环支持，提高API密钥安全性
  - 增强了代理API配置选项
  - 改进了自动注入功能
  - 添加了缓存管理命令

- **Bug修复**：
  - 修复了在Windows系统上的路径问题
  - 解决了某些特殊字符导致的解析错误
  - 修复了多线程环境下的竞态条件

### v1.0.0 (2024年1月20日)

- 首次发布
- 基本功能：
  - 智能Payload生成
  - 扫描结果分析
  - 漏洞解释
  - 修复建议
  - 交互式CLI

## 贡献与反馈

我们欢迎社区贡献和反馈，以帮助改进SQLMap AI模块。

### 如何贡献

1. **提交问题**：如果您发现bug或有功能建议，请在GitHub上提交issue
2. **提交代码**：
   - Fork项目仓库
   - 创建您的功能分支 (`git checkout -b feature/amazing-feature`)
   - 提交您的更改 (`git commit -m 'Add some amazing feature'`)
   - 推送到分支 (`git push origin feature/amazing-feature`)
   - 提交Pull Request

3. **改进文档**：帮助我们改进文档，使其更清晰、更全面
4. **分享使用案例**：分享您使用SQLMap AI模块的经验和案例

### 开发指南

如果您想参与开发，请遵循以下指南：

1. **代码风格**：遵循PEP 8编码规范
2. **测试**：为新功能添加适当的测试
3. **文档**：为新功能或更改添加文档
4. **兼容性**：确保与现有SQLMap功能保持兼容

### 反馈渠道

- GitHub Issues: [https://github.com/your-repo/sqlmap-ai/issues](https://github.com/your-repo/sqlmap-ai/issues)
- 电子邮件: feedback@example.com
- 社区论坛: [SQLMap论坛](https://github.com/sqlmapproject/sqlmap/discussions)

## 许可证

SQLMap AI模块遵循与SQLMap相同的许可证，详见项目根目录的LICENSE文件。

### 许可说明

- 本项目采用GNU通用公共许可证v2.0（GPL-2.0）进行许可
- 您可以自由使用、修改和分发本软件
- 如果您分发修改版本，必须同样以GPL-2.0许可证发布
- 您必须在您的项目中包含原始许可证和版权声明
- 本软件不提供任何担保

完整的许可证文本请参见[LICENSE](LICENSE)文件。

### 第三方组件

本项目使用了以下第三方组件，它们可能有自己的许可证：

- SQLMap: [GPL-2.0](https://github.com/sqlmapproject/sqlmap/blob/master/LICENSE)
- 其他依赖库的许可证信息请参见各自的文档

### 免责声明

本工具仅用于合法的安全测试和教育目的。使用本工具对未经授权的系统进行测试是违法的。用户必须遵守所有适用的法律法规，并获得适当的授权后才能使用本工具进行安全测试。

作者和贡献者对因使用本工具而导致的任何直接或间接损害不承担任何责任。
