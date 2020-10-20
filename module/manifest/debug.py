from common.PrintUtils import *
from common.Vulnerability import *

class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "Debuggable",
            "Author": "xxx",
            "Date": "2020.10.20",
            "Description": "检测应用是否允许被调试",
            "Reference": [
                "http://01hackcode.com/wiki/6.6",

            ],
        }
        self.status = False


    def run(self):

        allow_debug = self.apk.get_attribute_value("application", "debuggable")

        level = INFO
        content = f"\t{allow_debug}"
        poc = None
        suggestion = None

        if allow_debug.lower() == "true":
            level = HIGH
            poc = f"""{RED}
    BackupPOC:
        >>> adb backup -f back.ab -noapk {self.apk.get_package()}
    Install App on other Phone.
    RecoveryPOC:
        >>> adb restore back.ab{END}
"""
            suggestion = f"\t{RED}设置AndroidManifest.xml的debuggable标志为false{END}"


        vuln = Vulnerable(name=self.module_info['Name'],
                          level=level,
                          content=content,
                          poc=poc,
                          suggestion=suggestion,
                          )
        self.status = True

        return {
            "status": self.status,
            'result': vuln
        }