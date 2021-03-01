from common.Vulnerability import *
from common.PrintUtils import *

class Module:
    def __init__(self, apk, dx=None):
        self.apk = apk
        self.dx = dx
        self.module_info = {
            "Name": "SSL Connection",
            "Author": "xxx",
            "Date": "2021.01.25",
            "Description": "检测有无使用SSL安全协议",
            "Reference": [
                "http://01hackcode.com/wiki/10.1",
            ],
        }

        self.status = False

    def run(self):

        return {
            "status": self.status,
            'result': None
        }