from common.Vulnerability import *
from common.PrintUtils import *
from androguard.core.bytecodes import dvm
from androguard.decompiler.decompiler import DecompilerJADX
from config.config import JADX_PATH
from androguard.core.analysis.analysis import Analysis


class Module:
    def __init__(self, apk, decomplier):
        self.apk = apk
        self.decomplier = decomplier
        self.module_info = {
            "Name": "SQLite Encryption Extension",
            "Author": "xxx",
            "Date": "2021.01.25",
            "Description": '''检查SQLite是否使用了SQLite Encryption Extension插件
SEE是一个数据库加密扩展插件，允许app读取和写入加密的数据库文件，是SQLite的加密版本(收费版)，提供以下的加密方式：RC4、AES-128 in OFB mode、AES-128 in CCM mode、AES-256 in OFB mode''',
            "Reference": [
                "http://01hackcode.com/wiki/9.2",
            ],
        }
        """
        使用了SQLCipher开源库会产生”Lorg/sqlite/database/sqlite/SQLiteDatabase”的包路径，只需在包路径中查找是否存在该路径的包名即可。
        """
        self.status = False

    def run(self):

        data = {
            'sqlite_see': {
                'title': self.module_info['Name'],
                'desc': self.module_info['Description'],
                'code': [],
                'suggestion': [],
                'level': 1,
                'res': False

            }
        }

        vuln_class = 'Lorg/sqlite/database/sqlite/SQLiteDatabase'
        res = False
        content = ""
        suggestion = ""
        poc = ""

        # for dex in self.apk.get_all_dex():
        #     d = dvm.DalvikVMFormat(dex)
        #     dx = Analysis(d)
        #     decompiler = DecompilerJADX(d, dx, jadx=JADX_PATH)
        #     d.set_decompiler(decompiler)
        for d in self.decomplier:
            for n in d.get_classes():
                if vuln_class in n.get_name().decode():
                    # data['sqlite_see']['code'].append(n.get_name().decode())
                    data['sqlite_see']['code'].append(n.get_source())
                    res = True
                    break
            if res:
                self.status = True
                data['sqlite_see']['res'] = self.status
                data['sqlite_see']['suggestion'].append("禁用该数据库插件.")
                suggestion = content = "禁用该数据库插件."

            else:
                print('Not found..')



        vuln = Vulnerable(name=self.module_info['Name'],
                          level=LOW,
                          content=content,
                          suggestion=suggestion,
                          poc=poc,
                          data=data
                          )

        self.status = True
        return {
            "status": self.status,
            'result': vuln
        }
