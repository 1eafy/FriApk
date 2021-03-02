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
        data = {'permission': {
            'title': self.module_info['Name'],
            "p_list": [

            ],
            'res': True,
        }}
        content = ""
        color = ""
        for p in self.apk.get_permissions():
            if p in allPermission.keys():
                permission_level = allPermission[p].get("level", "N")
                description = allPermission[p].get("description")
                color = RED if permission_level == "D" else ""
                l = 1 if permission_level == "D" else 0
            else:
                description = "应用自定义权限"
                l = 0
            content += f"\t{color}{p}: {description}{END}\n"
            data['permission']['p_list'].append({'level': l, 'name': p, 'des': description})

        # print(content)
        suggestion = "\t用户可针对应用使用场景选择性给予权限"
        data['permission']['suggestion'] = suggestion
        # print(data)
        vuln = Vulnerable(name=self.module_info['Name'],
                          level=INFO,
                          content=content,
                          suggestion=suggestion,
                          data=data,
                          )

        self.status = True

        return {
            "status": self.status,
            'result': vuln
        }
