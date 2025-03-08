#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

try:
    import sys

    sys.dont_write_bytecode = True

    try:
        __import__("lib.utils.versioncheck")  # this has to be the first non-standard import
    except ImportError:
        sys.exit("[!] wrong installation detected (missing modules). Visit 'https://github.com/sqlmapproject/sqlmap/#installation' for further details")

    import bdb
    import glob
    import inspect
    import json
    import logging
    import os
    import re
    import shutil
    import sys
    import tempfile
    import threading
    import time
    import traceback
    import warnings

    if "--deprecations" not in sys.argv:
        warnings.filterwarnings(action="ignore", category=DeprecationWarning)
    else:
        warnings.resetwarnings()
        warnings.filterwarnings(action="ignore", message="'crypt'", category=DeprecationWarning)
        warnings.simplefilter("ignore", category=ImportWarning)
        if sys.version_info >= (3, 0):
            warnings.simplefilter("ignore", category=ResourceWarning)

    warnings.filterwarnings(action="ignore", message="Python 2 is no longer supported")
    warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*using a very old release", category=UserWarning)
    warnings.filterwarnings(action="ignore", message=".*default buffer size will be used", category=RuntimeWarning)
    warnings.filterwarnings(action="ignore", category=UserWarning, module="psycopg2")

    from lib.core.data import logger

    from lib.core.common import banner
    from lib.core.common import checkPipedInput
    from lib.core.common import checkSums
    from lib.core.common import createGithubIssue
    from lib.core.common import dataToStdout
    from lib.core.common import extractRegexResult
    from lib.core.common import filterNone
    from lib.core.common import getDaysFromLastUpdate
    from lib.core.common import getFileItems
    from lib.core.common import getSafeExString
    from lib.core.common import maskSensitiveData
    from lib.core.common import openFile
    from lib.core.common import setPaths
    from lib.core.common import weAreFrozen
    from lib.core.convert import getUnicode
    from lib.core.common import setColor
    from lib.core.common import unhandledExceptionMessage
    from lib.core.compat import LooseVersion
    from lib.core.compat import xrange
    from lib.core.data import cmdLineOptions
    from lib.core.data import conf
    from lib.core.data import kb
    from lib.core.datatype import OrderedSet
    from lib.core.enums import MKSTEMP_PREFIX
    from lib.core.exception import SqlmapBaseException
    from lib.core.exception import SqlmapShellQuitException
    from lib.core.exception import SqlmapSilentQuitException
    from lib.core.exception import SqlmapUserQuitException
    from lib.core.option import init
    from lib.core.option import initOptions
    from lib.core.option import _cleanupOptions
    from lib.core.patch import dirtyPatches
    from lib.core.patch import resolveCrossReferences
    from lib.core.settings import GIT_PAGE
    from lib.core.settings import IS_WIN
    from lib.core.settings import LAST_UPDATE_NAGGING_DAYS
    from lib.core.settings import LEGAL_DISCLAIMER
    from lib.core.settings import THREAD_FINALIZATION_TIMEOUT
    from lib.core.settings import UNICODE_ENCODING
    from lib.core.settings import VERSION
    from lib.core.shell import clearHistory
    from lib.parse.cmdline import cmdLineParser
    from lib.utils.crawler import crawl
    from lib.controller.controller import action
    from ai_module.cli import AICLI
    from ai_module.core import AICore
except KeyboardInterrupt:
    errMsg = "user aborted"

    if "logger" in globals():
        logger.critical(errMsg)
        raise SystemExit
    else:
        import time
        sys.exit("\r[%s] [CRITICAL] %s" % (time.strftime("%X"), errMsg))

def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    try:
        _ = sys.executable if weAreFrozen() else __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)

    return getUnicode(os.path.dirname(os.path.realpath(_)), encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)

def checkEnvironment():
    try:
        os.path.isdir(modulePath())
    except UnicodeEncodeError:
        errMsg = "your system does not properly handle non-ASCII paths. "
        errMsg += "Please move the sqlmap's directory to the other location"
        logger.critical(errMsg)
        raise SystemExit

    if LooseVersion(VERSION) < LooseVersion("1.0"):
        errMsg = "your runtime environment (e.g. PYTHONPATH) is "
        errMsg += "broken. Please make sure that you are not running "
        errMsg += "newer versions of sqlmap with runtime scripts for older "
        errMsg += "versions"
        logger.critical(errMsg)
        raise SystemExit

    # Patch for pip (import) environment
    if "sqlmap.sqlmap" in sys.modules:
        for _ in ("cmdLineOptions", "conf", "kb"):
            globals()[_] = getattr(sys.modules["lib.core.data"], _)

        for _ in ("SqlmapBaseException", "SqlmapShellQuitException", "SqlmapSilentQuitException", "SqlmapUserQuitException"):
            globals()[_] = getattr(sys.modules["lib.core.exception"], _)

def main():
    """
    Main function of sqlmap when running from command line.
    """

    try:
        # 初始化命令行参数
        args = cmdLineParser()
        
        # 初始化配置
        initOptions(args)
        
        # 初始化data模块
        from lib.core.data import init as dataInit
        dataInit()
        
        # 初始化环境
        checkEnvironment()
        setPaths(modulePath())
        banner()
        
        # 显示免责声明
        if not any((conf.api, conf.get("disableStdOut"), conf.updateAll)):
            dataToStdout("[!] legal disclaimer: %s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
            dataToStdout("[*] starting @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        # 初始化
        init()
        
        # 如果启用了AI CLI模式
        if conf.aiCli:
            from ai_module.cli import AICLI
            print("[*] 欢迎使用SQLMap AI交互式命令行界面")
            print("[*] 输入'help'或'?'获取可用命令")
            print("[*] 输入'exit'或'quit'退出")
            AICLI().cmdloop()
            return
            
        if conf.smartPayload or conf.aiAnalysis or conf.explainVuln or conf.suggestFix:
            ai = AICore()
            if not ai.check_api_key():
                logger.error("未找到有效的API密钥，请先配置API密钥")
                return

        # 原有的SQLMap逻辑
        if conf.updateAll:
            update()
            return

        if conf.smokeTest:
            smokeTest()
            return

        if conf.vulnTest:
            vulnTest()
            return

        if conf.bedTest:
            bedTest()
            return

        if conf.dependencies:
            dependencies()
            return

        if conf.purge:
            purge()
            return

        if conf.listTampers:
            listTampers()
            return

        start()

    except KeyboardInterrupt:
        print()

    except SqlmapUserQuitException:
        errMsg = "user quit"
        logger.error(errMsg)

    except SqlmapSilentQuitException:
        pass

    except SqlmapBaseException as ex:
        errMsg = getSafeExString(ex)
        logger.critical(errMsg)

    finally:
        if conf.get("showTime"):
            logger.info("total time elapsed: %s" % clearConsoleLine(getRunningTime()))

        kb.threadContinue = False
        kb.threadException = True

        if conf.get("hashDB"):
            conf.hashDB.flush(True)

        if conf.get("harFile"):
            conf.harFile.close()

        if conf.get("api"):
            conf.database.disconnect()

        clearHistory()
        _cleanupOptions()

def start():
    """
    主要的扫描功能入口
    """
    if conf.smartPayload:
        try:
            ai = AICore()
            payload = ai.generate_smart_payload(conf.dbms, conf.technique)
            logger.info(f"AI生成的智能payload: {payload}")
            # 使用生成的payload进行测试
        except Exception as e:
            logger.error(f"生成智能payload失败: {e}")
            logger.info("继续使用标准的SQLMap扫描...")

    # 调用原始的SQLMap扫描函数
    from lib.controller.controller import start as original_start
    original_start()

    if conf.aiAnalysis:
        try:
            ai = AICore()
            
            # 构建扫描结果的摘要
            scan_summary = ""
            
            # 检查是否有注入点
            if kb.injections and len(kb.injections) > 0:
                scan_summary += "SQLMap扫描发现以下注入点:\n"
                for i, injection in enumerate(kb.injections):
                    scan_summary += f"注入点 {i+1}:\n"
                    scan_summary += f"  参数: {injection.parameter}\n"
                    scan_summary += f"  位置: {injection.place}\n"
                    scan_summary += f"  类型: {injection.data.get('type', '未知')}\n"
                    scan_summary += f"  标题: {injection.data.get('title', '未知')}\n"
                    scan_summary += f"  Payload: {injection.data.get('payload', '未知')}\n"
                
                # 添加数据库信息
                if conf.dbms:
                    scan_summary += f"数据库类型: {conf.dbms}\n"
                
                # 添加目标信息
                scan_summary += f"目标URL: {conf.url}\n"
            else:
                scan_summary = "SQLMap扫描未发现任何SQL注入漏洞。"
            
            # 调用AI分析
            analysis = ai.analyze_scan_results(scan_summary)
            logger.info("AI分析结果:")
            logger.info(analysis)

            # 如果启用了漏洞解释功能
            if conf.explainVuln and kb.injections and len(kb.injections) > 0:
                try:
                    ai = AICore()
                    # 使用实际检测到的数据库类型
                    detected_dbms = conf.dbms or "MySQL"
                    vuln_type = "SQL注入"
                    explanation = ai.explain_vulnerability(vuln_type, detected_dbms)
                    logger.info("漏洞解释:")
                    logger.info(explanation)
                except Exception as e:
                    logger.error(f"解释漏洞失败: {e}")

            # 如果启用了修复建议功能
            if conf.suggestFix and kb.injections and len(kb.injections) > 0:
                try:
                    ai = AICore()
                    # 使用实际检测到的数据库类型
                    detected_dbms = conf.dbms or "MySQL"
                    vuln_type = "SQL注入"
                    
                    # 使用实际的payload作为示例代码
                    if kb.injections[0].data.get('payload'):
                        code_sample = f"SELECT * FROM users WHERE id = {kb.injections[0].data.get('payload')}"
                    else:
                        code_sample = "SELECT * FROM users WHERE id = '1' OR '1'='1'"
                        
                    fixes = ai.suggest_fixes(vuln_type, detected_dbms, code_sample)
                    logger.info("修复建议:")
                    logger.info(fixes)
                except Exception as e:
                    logger.error(f"生成修复建议失败: {e}")
        except Exception as e:
            logger.error(f"AI分析失败: {e}")
            logger.info("继续使用标准的SQLMap扫描结果...")

if __name__ == "__main__":
    main()
