from common.Vulnerability import *
from common.PrintUtils import *

class Module:
    def __init__(self, apk):
        self.apk = apk
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

        self.status = False

    def run(self):

        return {
            "status": self.status,
            'result': None
        }