from common.PrintUtils import *
from common.Vulnerability import *

NS = "{http://schemas.android.com/apk/res/android}"


class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "Component Exported",
            "Author": "xxx",
            "Date": "2020.10.20",
            "Description": "Activity、activity-alias、service、receiver组件对外暴露会导致数据泄露和恶意的dos攻击",
            "Reference": [
                "https://blog.csdn.net/watermusicyes/article/details/46460347",
                "http://01hackcode.com/wiki/7.1",
                "https://www.jianshu.com/p/8a4e8f857db5",
                "https://blog.51cto.com/laoyinga/2053036",

            ],
        }

        self.status = False

    def run(self):

        exported_tag = {'activity': "",
                        'service': "",
                        'provider': "",
                        'receiver': "",
                        }
        content = ""

        # for tag in exported_tag.keys():
        #     tag_name_color = ""
        #     for v in self.apk.find_tags(tag, exported="true"):
        #         tag_name = v.attrib['{http://schemas.android.com/apk/res/android}name']
        #         tag_name_color += f"\n\t\t{tag_name}"
        #     exported_tag[tag] = tag_name_color
        #
        # for k, v in exported_tag.items():
        #     content += f'\t{k.capitalize()}:{YELLOW}{v}{END}\n'

        danger_value = ["normal", "dangerous"]
        save_value = ["signature", "signatureOrSystem"]
        for tag in exported_tag:
            for v in self.apk.find_tags(tag):
                if tag == "activity" or tag == "service" or tag == "receiver":
                    tag_name = self.get_value(v, "name")
                    flag = self.get_value(v, "exported").lower()
                    if flag == "true":
                        # 当前activity 存在exported 且为 true
                        # TODO 需要继续判断当前Activity是否有子节点intent-filter, 判断category标签不是”launcher”
                        protect = self.get_value(v, "protectionLevel")
                        permission = self.get_value(v, "permission")
                        if (protect != "none" or protect in save_value) or (permission != "none"):
                            pass
                            # print(f"save {tag}:{tag_name}-{protect}-{permission}")
                        else:
                            exported_tag[tag] += f"\t\t{YELLOW}{tag_name}{END}\n"
                            printRed(f"danger {tag} {tag_name}")
                    elif flag == 'none':
                        # 当前activity 未设置exported
                        for i in list(v):
                            if i.tag == "intent-filter":
                                # 当存在intent-filter时, exported默认值为true
                                # print(f"{tag_name} 未设置exported,但存在intent-filter")
                                # TODO 需要继续判断当前Activity是否有子节点intent-filter, 判断category标签不是”launcher”
                                protect = self.get_value(v, "protectionLevel")
                                permission = self.get_value(v, "permission")
                                if (protect != "none" or protect in save_value) or (permission != "none"):
                                    # print(f"save {tag}:{tag_name}-{protect}-{permission}")
                                    pass
                                else:
                                    print(f"danger {tag} {tag_name}")
                                    exported_tag[tag] += f"\t\t{YELLOW}{tag_name}{END}\n"
                                    break
                    else:
                        pass

                else:
                    # Content Provider
                    # Android sdk版本大于16：默认false
                    # **Android sdk版本小于等于16 **：默认true

                    # printRed(f"{tag}:{v.get(f'{NS}exported', False)}")
                    pass

        suggestion = ""
        print(exported_tag)
        for k, v in exported_tag.items():
            print(f"\t{k}\n{v}\n")


        vuln = Vulnerable(name=self.module_info['Name'],
                          level=MIDDLE,
                          content=content,
                          suggestion=None
                          )

        return {
            "status": self.status,
            'result': None
        }

    def get_value(self, tag, attr):
        return tag.get(f'{NS}{attr}', "none")
