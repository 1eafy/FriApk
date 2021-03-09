from common.Vulnerability import *
from common.PrintUtils import *
from androguard.core.bytecodes import dvm
import re

class Module:
    def __init__(self, apk, decomplier):
        self.apk = apk
        self.decomplier = decomplier
        self.module_info = {
            "Name": "DES Weak Mode",
            "Author": "xxx",
            "Date": "2021.01.25",
            "Description": '''全性要求高的应用程序必须避免使用不安全的或者强度弱的加密算法，现代计算机的计算能力使得攻击者通过暴力破解可以攻破强度弱的算法。例如，数据加密标准算法DES(密钥默认是56位长度、算法半公开、迭代次数少)是极度不安全的，使用类似EFF（Electronic Frontier Foundaton） Deep Crack的计算机在一天内可以暴力破解由DES加密的消息。''',
            "Reference": [
                "http://01hackcode.com/wiki/11.1",
            ],
        }
        '''
        通过正则表达式"DES/(\w){3}/.+Padding"匹配字符串常量
        '''
        self.status = False
        

    def run(self):

        suggestion = '建议使用安全性更高的AES加密算法'
        poc = ""

        data = {
            'des_weak':{
                'title': self.module_info['Name'],
                'desc': self.module_info['Description'],
                'type': [],
                'suggestion': [],
                'poc': "",
                'res': False
            }
        }

        content = ""

        r = b"DES/(\w){3}/.+Padding"
        # for dex in self.apk.get_all_dex():
        #     d = dvm.DalvikVMFormat(dex)
        for d in self.decomplier:
            try:
                string_list = d.get_strings()
            except Exception as e:
                print(e)
                continue
            for s in string_list:
                a = re.search(r , s, re.IGNORECASE)
                if a:
                    # content[name] = content[name] + "\n\t" + a.group().decode()
                    content += a.group().decode()
                    data['des_weak']['type'].append(a.group().decode())

        self.status = len(data['des_weak']['type']) > 0
        data['des_weak']['res'] = self.status
        if self.status: data['des_weak']['suggestion'].append(suggestion)
        self.status = True

        vuln = Vulnerable(name=self.module_info['Name'],
                          level=LOW,
                          content=content,
                          suggestion=suggestion,
                          poc=poc,
                          data=data
                          )

        return {
            "status": self.status,
            'result': vuln
        }