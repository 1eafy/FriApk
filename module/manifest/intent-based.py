from common.Vulnerability import *
from common.PrintUtils import *

class Module:
    def __init__(self, apk, decomplier):
        self.apk = apk
        self.decomplier = decomplier
        self.module_info = {
            "Name": "Intent-Based攻击检测",
            "Author": "xxx",
            "Date": "2020.10.21",
            "Description": "在AndroidManifest文件中定义了android.intent.category.BROWSABLE属性的组件，可以通过浏览器唤起，这会导致远程命令执行漏洞攻击",
            "Reference": [
                "https://blog.csdn.net/l173864930/article/details/36951805",
                "http://01hackcode.com/wiki/7.6",
                "https://segmentfault.com/a/1190000007747812"
            ],
        }

        self.status = False

    def run(self):
        vuln_value = "android.intent.category.BROWSABLE"
        tag = ['activity',
                'service',
                'provider',
                'receiver',
               ]

        vuln_component = []
        data = {

            'intent-based': {
                'title': self.module_info['Name'],
                'vuln_component': [],
                'res': False,
                'suggestion': [],
                'desc': self.module_info['Description']
            },

        }
        content = ""
        for t in tag:
            for tag_name in self.apk.get_all_attribute_value(t, "name"):
                # 根据标签名筛选所有intent、category
                i = self.apk.get_intent_filters(t, tag_name)
                if 'category' in i.keys():
                    if vuln_value in i.get('category'):
                        vuln_component.append("\t"+tag_name)
                        data['intent-based']['vuln_component'].append(tag_name)

        #
        # print(vuln_component)
        # print('++++++++++++++++++++++++++++++++++++++')
        content = '\n'.join(vuln_component)
        self.status = len(content) > 0
        data['intent-based']['res'] = self.status
        suggestion = ""
        if self.status:
            suggestion = """
                在AndroidManifest文件中定义了android.intent.category.BROWSABLE属性的组件，可以通过浏览器唤起，这会导致远程命令执行漏洞攻击。建议：
                (1)APP中任何接收外部输入数据的地方都是潜在的攻击点，过滤检查来自网页的参数。
                (2)不要通过网页传输敏感信息，有的网站为了引导已经登录的用户到APP上使用，会使用脚本动态的生成URL Scheme的参数，其中包括了用户名、密码或者登录态token等敏感信息，让用户打开APP直接就登录了。恶意应用也可以注册相同的URL Sechme来截取这些敏感信息。Android系统会让用户选择使用哪个应用打开链接，但是如果用户不注意，就会使用恶意应用打开，导致敏感信息泄露或者其他风险。"""
            data['intent-based']['suggestion'].append('1. APP中任何接收外部输入数据的地方都是潜在的攻击点，过滤检查来自网页的参数。')
            data['intent-based']['suggestion'].append('2. 不要通过网页传输敏感信息，有的网站为了引导已经登录的用户到APP上使用，会使用脚本动态的生成URL Scheme的参数，其中包括了用户名、密码或者登录态token等敏感信息，让用户打开APP直接就登录了。恶意应用也可以注册相同的URL Sechme来截取这些敏感信息。Android系统会让用户选择使用哪个应用打开链接，但是如果用户不注意，就会使用恶意应用打开，导致敏感信息泄露或者其他风险。')
            data['intent-based']['level'] = 1
        # print(data)
        self.status = True
        vuln = Vulnerable(name=self.module_info['Name'],
                          level=LOW,
                          content=content,
                          suggestion=suggestion,
                          data=data,
                          )


        # self.status = True

        return {
            "status": self.status,
            'result': vuln
        }