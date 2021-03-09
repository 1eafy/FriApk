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
    def __init__(self, apk, decomplier):
        self.apk = apk
        self.decomplier = decomplier
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
        data = {

            'sen_info':{
                'title': self.module_info['Name'],
                'type':{
                    'Mail': [],
                    'Domain': [],
                    'Phone': [],
                    'IP': [],
                }

            }
        }
        # regs = {
        #     "Domain": b"(http://|https://)(.*)",
        # }
        from common.reg import regs
        content = {
            "Domain": "",
            'IP': "",
            'Mail': ""
        }
        # for dex in self.apk.get_all_dex():
        #     d = dvm.DalvikVMFormat(dex)
        for d in self.decomplier:
            try:
                strings_list = d.get_strings()
            except Exception as e:
                print(e)
                continue
            for s in strings_list:
                for name, reg in regs.items():
                    a = re.search(reg , s, re.IGNORECASE)
                    if a:
                        content[name] = content[name] + "\n\t" + a.group().decode()
                        data['sen_info']['type'][name].append(a.group().decode())

        self.status = len(content['Domain']) > 0
        # print(data)
        data['sen_info']['res'] = True
        data['sen_info']['level'] = 0

        vuln = Vulnerable(name=self.module_info['Name'],
                          level=INFO,
                          content=content["Domain"],
                          data=data)
        return {
            "status": True,
            'result': vuln,
        }