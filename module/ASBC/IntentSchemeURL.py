from androguard.core.bytecodes import dvm
from androguard.decompiler.dad.decompile import DvMethod
from androguard.core.analysis.analysis import Analysis
from pprint import pprint as pp
from androguard.decompiler.decompiler import DecompilerJADX
from config.config import JADX_PATH

class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "Intent Scheme URL漏洞攻击检测",
            "Author": "xxx",
            "Date": "2020.10.21",
            "Description": """Intent Scheme URI是一种特殊的URL格式，用来通过Web页面启动已安装应用的Activity组件，大多数主流浏览器都支持此功能。
Android Browser的攻击手段——Intent Scheme URLs攻击。这种攻击方式利用了浏览器保护措施的不足，通过浏览器作为桥梁间接实现Intend-Based攻击。相比于普通Intend-Based攻击，这种方式极具隐蔽性，
如果在app中，没有检查获取到的load_url的值，攻击者可以构造钓鱼网站，诱导用户点击加载，就可以盗取用户信息。所以，对Intent URI的处理不当时，就会导致基于Intent的攻击。""",
            "Reference": [
                "http://01hackcode.com/wiki/7.7",
                "https://blog.csdn.net/l173864930/article/details/36951805?spm=a313e.7916648.0.0.28c26611Ag1xh8",

            ],
        }

        self.status = False
# 腾讯金刚检测Diva：https://service.security.tencent.com/uploadimg_dir/jingang/82ab8b2193b3cfb1c737e3a786be363a.html
    # c7c91424ab41179ead7186cf586c8a3d
    def run(self):
        # for dex in self.apk.get_all_dex():
        #     d = dvm.DalvikVMFormat(dex)
        #     dx = Analysis(d)
        #     decompiler = DecompilerJADX(d, dx, jadx=JADX_PATH)
        #     d.set_decompiler(decompiler)
        #
        #     for cls in d.get_classes():
        #         print(cls.get_name())
        #         print(cls.get_source())
        #         break

        return {
            "status": False,
            'result': None,
        }

    def get_classes(self):

        """
        获取所有类
        :return:
        """
        # dx = dvm.DalvikVMFormat(dex)
        # # print(dx.get_len_methods())
        # # if i>1: break
        # cls = dx.get_classes()
        # for c in cls:
        #     if "InsecureDataStorage2Activity" in c.name.decode():
        #         cls_m = dx.get_methods_class(c.name)
        #         for m in cls_m:
        #             des = dx.get_methods_descriptor(c.name.decode(), m.name.decode())
        #             for d in des:
        #                 print(d.__dict__)
        pass





