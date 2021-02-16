from common.Vulnerability import *
from common.PrintUtils import *

class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "SQLCipher check",
            "Author": "xxx",
            "Date": "2021.01.25",
            "Description": '''检查SQLite是否使用了SQLCipher开源库。SQLCipher是对整个数据库文件进行加密。''',
            "Reference": [
                "http://01hackcode.com/wiki/9.1",
            ],
        }

        self.status = False

    def run(self):


        return {
            "status": self.status,
            'result': None
        }