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

        # 获取debuggable属性值
        allow_debug = self.apk.get_attribute_value("application", "debuggable")
        data = {

            'allow_debug': {
                'title': self.module_info['Name'],
                'res': True,
            },


        }
        level = INFO
        content = f"\t{allow_debug}"
        poc = None
        suggestion = None

        if allow_debug and allow_debug.lower() == "true":
            level = HIGH
            self.status = True
            poc = None
            suggestion = f"\t{RED}设置AndroidManifest.xml的debuggable标志为false{END}"


        data['allow_debug']['level'] = level
        data['allow_debug']['suggestion'] = suggestion
        data['allow_debug']['poc'] = poc
        data['allow_debug']['res'] = self.status
        self.status = True
        vuln = Vulnerable(name=self.module_info['Name'],
                          level=level,
                          content=content,
                          poc=poc,
                          suggestion=suggestion,
                          data=data,
                          )

        return {
            "status": self.status,
            'result': vuln
        }