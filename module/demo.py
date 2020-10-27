from common.Vulnerability import *
from common.PrintUtils import *

class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "",
            "Author": "xxx",
            "Date": "2020.10.21",
            "Description": "",
            "Reference": [
                "",
            ],
        }

        self.status = False

    def run(self):

        return {
            "status": self.status,
            'result': None
        }