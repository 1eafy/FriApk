from common.Vulnerability import *
from common.PrintUtils import *
from common.protect import allPermission

class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "Permission",
            "Author": "xxx",
            "Date": "2020.10.21",
            "Description": "检测权限申请情况, 高亮危险权限, 用户可针对应用使用场景选择性给予权限",
            "Reference": [
                "",
            ],
        }

        self.status = False

    def run(self):

        content = ""
        color = ""
        for p in self.apk.get_permissions():
            if p in allPermission.keys():
                permission_level = allPermission[p].get("level", "N")
                description = allPermission[p].get("description")
                color = RED if permission_level == "D" else ""
            else:
                description = "用户自定义权限"
            content += f"\t{color}{p}: {description}{END}\n"

        # print(content)
        suggestion = "\t用户可针对应用使用场景选择性给予权限"

        vuln = Vulnerable(name=self.module_info['Name'],
                          level=INFO,
                          content=content,
                          suggestion=suggestion,
                          )

        self.status = False

        return {
            "status": self.status,
            'result': vuln
        }