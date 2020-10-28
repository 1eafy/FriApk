from common.Vulnerability import *
from common.PrintUtils import *
from androguard.core.bytecodes import dvm
import re
from common.reg import *
from androguard.decompiler.dad.decompile import DvMethod
from androguard.core.analysis.analysis import Analysis
from pprint import pprint as pp
from androguard.decompiler.decompiler import DecompilerJADX
from config.config import JADX_PATH


class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "敏感信息匹配",
            "Author": "xxx",
            "Date": "2020.10.28",
            "Description": "遍历Apk源码中所有字符串，使用正则匹配所有邮箱、域名等等，该模块可用于渗透测试前期信息收集",
            "Reference": [
                "",
            ],
        }

        self.status = False

    def run(self):
        regs = {
            "Domain": b"(http://|https://)(.*)",
        }
        content = {
            "Domain": "",
        }
        for dex in self.apk.get_all_dex():
            d = dvm.DalvikVMFormat(dex)
            for s in d.get_strings():
                for name, reg in regs.items():
                    a = re.search(reg , s, re.IGNORECASE)
                    if a:
                        content[name] = content[name] + "\n\t" + a.group().decode()

        self.status = len(content['Domain']) > 0
        vuln = Vulnerable(name=self.module_info['Name'],
                          level=INFO,
                          content=content["Domain"])
        return {
            "status": True,
            'result': vuln,
        }