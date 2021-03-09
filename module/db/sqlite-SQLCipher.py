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
            "Name": "SQLCipher",
            "Author": "xxx",
            "Date": "2021.01.25",
            "Description": '''检查SQLite是否使用了SQLCipher开源库。SQLCipher是对整个数据库文件进行加密。''',
            "Reference": [
                "http://01hackcode.com/wiki/9.1",
            ],
        }

        self.status = False

    def run(self):
        data = {
            'sql_cipher': {
                'title': self.module_info['Name'],
                'desc': self.module_info['Description'],
                'code': [],
                'suggestion': [],
                'level': 1,
                'res': False

            }
        }

        vuln_class = 'Lnet/sqlcipher/database/SQLiteDatabase'
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
                    data['sql_cipher']['code'].append(n.get_source())
                    res = True
                    break
        if res:
            self.status = True
            data['sql_cipher']['res'] = self.status
            data['sql_cipher']['suggestion'].append("无")
            suggestion = content = "无"

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
