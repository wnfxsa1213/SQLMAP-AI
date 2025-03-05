#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.datatype import AttribDict
from lib.core.log import LOGGER
import os

class SqlmapAttribDict(AttribDict):
    def __getattr__(self, item):
        try:
            return self.__getitem__(item)
        except KeyError:
            return None

# Get SQLMAP_ROOT_PATH
SQLMAP_ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

# sqlmap paths
paths = SqlmapAttribDict()
paths.SQLMAP_ROOT_PATH = SQLMAP_ROOT_PATH
paths.SQL_KEYWORDS = os.path.join(SQLMAP_ROOT_PATH, "data", "keywords.txt")  # 修改为keywords.txt

# object to store original command line options
cmdLineOptions = SqlmapAttribDict()

# object to store merged options (command line, configuration file and default options)
mergedOptions = SqlmapAttribDict()

# object to share within function and classes command
# line options and settings
conf = SqlmapAttribDict()
conf.encoding = "utf-8"

# object to share within function and classes results
kb = SqlmapAttribDict()
kb.keywords = set()  # 先设置一个空集合作为默认值
kb.encoding = "utf-8"  # 设置默认编码

# object with each database management system specific queries
queries = {}

# logger
logger = LOGGER

def init():
    """
    初始化一些需要在模块完全加载后才能设置的值
    """
    from lib.core.common import getFileItems
    
    if hasattr(paths, "SQL_KEYWORDS"):
        try:
            kb.keywords = set(getFileItems(paths.SQL_KEYWORDS))
        except:
            pass  # 保持默认的空集合

    if hasattr(conf, "encoding"):
        kb.encoding = conf.encoding
