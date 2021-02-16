from common.Vulnerability import *
from common.PrintUtils import *

class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "DES weak mode",
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

        return {
            "status": self.status,
            'result': None
        }