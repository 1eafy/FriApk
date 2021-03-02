from common.PrintUtils import *
from common.Vulnerability import *
from androguard.core.bytecodes import dvm
from androguard.decompiler.dad.decompile import DvMethod
from androguard.core.analysis.analysis import Analysis
from pprint import pprint as pp
from androguard.decompiler.decompiler import DecompilerJADX
from config.config import JADX_PATH
import re

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
                        'provider': {},
                        'receiver': "",
                        }
        content = ""

        data = {
            "component_exported": {
                'type':{
                    'activity': [],
                    'service': [],
                    'provider': [],
                    'receiver': [],
                },
            'suggestion': [],
            'poc': [],
            'res': True,
            'desc': self.module_info['Description'],
            'title': self.module_info['Name'],
        }}

        danger_value = ["normal", "dangerous"]
        # save_value = ["signature", "signatureOrSystem"]
        for tag in exported_tag:
            for v in self.apk.find_tags(tag):
                # 先获取相关属性值
                tag_name = self.get_value(v, "name")
                flag = self.get_value(v, "exported").lower()
                protect = self.get_value(v, "protectionLevel")
                permission = self.get_value(v, "permission")

                if tag == "activity" or tag == "service" or tag == "receiver":
                    if tag_name == self.apk.get_main_activity(): continue
                    if flag == "true":
                        # 当前组件 存在exported 且为 true
                        if (protect == "none" or protect in danger_value) and (permission == "none"):
                            # printRed(f"danger---{tag} {tag_name}")
                            exported_tag[tag] += f"\t\t{YELLOW}{tag_name}{END}\n"
                            data['component_exported']['type'][tag].append(tag_name)
                        else:
                            pass
                            # print(f"save {tag}:{tag_name}-{protect}-{permission}")

                    elif flag == 'none':
                        # 当前组件 未设置exported
                        for i in list(v):
                            if i.tag == "intent-filter":
                                for a in list(i):
                                    # 当存在intent-filter时, exported默认值为true
                                    # print(f"{tag_name} 未设置exported,但存在intent-filter")
                                    # protect = self.get_value(v, "protectionLevel")
                                    # permission = self.get_value(v, "permission")
                                    if a.tag == "action":
                                        if (permission == "none") and (protect == "none" or protect in danger_value):
                                            # print(f"danger {tag} {tag_name}")
                                            exported_tag[tag] += f"\t\t{YELLOW}{tag_name}{END}\n"
                                            data['component_exported']['type'][tag].append(tag_name)
                                            break
                                # 跳出二层循环
                                else:
                                    continue
                                break
                                # else:
                                #     # print(f"save {tag}:{tag_name}-{protect}-{permission}")
                                #     pass
                    else:
                        # 当前组件 exported设置为false
                        pass

                else:
                    # Content Provider
                    # Android sdk版本大于16：默认false
                    # **Android sdk版本小于等于16 **：默认true
                    # print(tag_name)
                    # printRed(self.apk.get_max_sdk_version())
                    # printRed(type(self.apk.get_min_sdk_version()))
                    # printRed(self.apk.get_target_sdk_version())
                    if flag == "true" or int(self.apk.get_min_sdk_version()) <= 16:
                        # exported_tag[tag] += f"\t\t{YELLOW}{tag_name}{END}\n"
                        exported_tag['provider'][tag_name] = ''
                        data['component_exported']['type']['provider'].append(tag_name)
                    else:
                        pass
                        # exported_tag[tag] += f"\t\t{BLUE}{tag_name}(根据Android SDK确认是否存在此风险, Android SDK >= 16){END}\n"
                        # data['component_exported'][tag].append(tag_name + "(根据Android SDK确认是否存在此风险, Android SDK >= 16)")

        suggestion = """
        1. 最小化组件暴露。对不会参与跨应用调用的组件添加android:exported="false"属性。
        2. 设置组件访问权限。对跨应用间调用的组件或者公开的receiver、service、activity和activity-alias设置权限，同时将权限的protectionLevel设置为"signature"或"signatureOrSystem"。
        3. 组件传输数据验证。对组件之间，特别是跨应用的组件之间的数据传入与返回做验证和增加异常处理，防止恶意调试数据传入，防止Dos攻击，更要防止敏感数据返回"""
        # data['component_exported']['suggestion'] = suggestion.replace(' ', '').replace('\t\n', '')
        data['component_exported']['suggestion'].append('1. 最小化组件暴露。对不会参与跨应用调用的组件添加android:exported="false"属性。')
        data['component_exported']['suggestion'].append('2. 设置组件访问权限。对跨应用间调用的组件或者公开的receiver、service、activity和activity-alias设置权限，同时将权限的protectionLevel设置为"signature"或"signatureOrSystem"。')
        data['component_exported']['suggestion'].append('3. 组件传输数据验证。对组件之间，特别是跨应用的组件之间的数据传入与返回做验证和增加异常处理，防止恶意调试数据传入，防止Dos攻击，更要防止敏感数据返回')
        # print(exported_tag)
        # for k, v in exported_tag.items():
        #     content += (f"\t{k.capitalize()}:\n{v}")

        # if len(exported_tag['provider']) == 31:
        c_uri = ""
        if len(exported_tag['provider']) > 0:
            for i, tag in enumerate(exported_tag['provider']):
                for dex in self.apk.get_all_dex():
                    d = dvm.DalvikVMFormat(dex)
                    dx = Analysis(d)
                    decompiler = DecompilerJADX(d, dx, jadx=JADX_PATH)
                    d.set_decompiler(decompiler)
                    # a = exported_tag['provider']
                    a = tag
                    a = a.replace('.', '/')
                    a = f"L{a};"
                    aaa = d.get_class(a)
                    if aaa:
                        src = aaa.get_source()
                        content_uri = re.search("""parse\("content://(.*)"\);""", src, re.IGNORECASE)
                        if content_uri:
                            c_uri = f"content://{content_uri.group(1)}"
                            # exported_tag['provider'] = YELLOW + "\t\t" + exported_tag[
                            #     'provider'] + "\n\t\t\t" + "URI: " + c_uri + END + "\n"
                            exported_tag['provider'][tag] = c_uri
                            data['component_exported']['type']['provider'][i] = tag + '(' +c_uri + ')'

            # for i in d.get_classes():
            #     if a == i.get_name().__str__():
            #         printRed(i.get_name().__str__())
        for k, v in exported_tag.items():
            content += (f"\t{k.capitalize()}:\n{v}")

        poc = """
        Activity POC:
            >>> adb shell am start -n 包名/组件路径
        Provider POC:
            >>> adb shell content [subcommand] [options]
            >>> adb shell content [query|insert|delete|read|secure|update|call|..] --uri ...
        """
        poc1 = """
Activity POC:
    >>> adb shell am start -n 包名/组件路径
Provider POC:
    >>> adb shell content [subcommand] [options]
    >>> adb shell content [query|insert|delete|read|secure|update|call|..] --uri ..."""
        data['component_exported']['poc'].append(poc1)
        # data['component_exported']['poc'].append('Activity POC:')
        # data['component_exported']['poc'].append('>>> adb shell am start -n 包名/组件路径')
        # data['component_exported']['poc'].append('Provider POC:')
        # data['component_exported']['poc'].append('>>> adb shell content [subcommand] [options]')
        # data['component_exported']['poc'].append('>>> adb shell content [query|insert|delete|read|secure|update|call|..] --uri ...')
        data['component_exported']['level'] = 1
        vuln = Vulnerable(name=self.module_info['Name'],
                          level=MIDDLE,
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

    def get_value(self, tag, attr):
        return tag.get(f'{NS}{attr}', "none")
