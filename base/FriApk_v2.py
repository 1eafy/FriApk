from re import search, findall
from base.PrintUtils import *
from common.Utils import *
from libs.androguard.core.bytecodes import apk
from libs.androguard.core.androconf import *
from importlib import util, import_module
from base.protect import *
from config.config import *
from xml.etree import ElementTree as ET
import importlib


class FriApk:
    def __init__(self, args):
        self.apk_filename = args.apk
        self.apk = None
        self.all_permission = []
        self.danger_permission = []
        self.modules = {}
        self.modules_load = []

        self.is_protect = False
        self.protect_type = ""
        # self._only_static_analyze = args.static_only
        self.vul_info = {
            "info": "",
            "level": 0,
            # TODO 完善检测漏洞结果信息

        }

    def load_apk(self):
        if is_android(self.apk_filename) == "APK":
            self.apk = apk.APK(self.apk_filename, testzip=False)
            if self.apk.is_valid_APK():
                self.all_permission = self.apk.get_permissions()
                self.is_protect, self.protect_type = self.get_protect_and_type()
                self.load_modules()
                self.show_certificate()
        else:
            printRed("[!] File is not APK.")

    def load_modules(self):
        for root, _, files in list(os.walk("module"))[1:-2]:
            module_type = findall(r"module\\(.*)", root)[0]
            if len(files):
                self.modules[module_type] = ['.'.join(['module', module_type, m[:-3]]) for m in files if
                                             m.endswith('py')]
        for module_type, modules in self.modules.items():
            for m in modules:
                if self.check_module(m):
                    aha = import_module(m)
                    try:
                        obj = aha.Module(self.apk)
                        result = obj.run()
                    except Exception as e:
                        print(f"[!] Load {m} Error.", e)
                    self.modules_load.append(aha)

    def check_module(self, module):
        """
            check module is usability

        :param module: module name
        :return: module spec
        """

        # print(f"[?] Check Module")
        module_spec = util.find_spec(module)
        # print(f"module_spec={module_spec}")
        if not module_spec: print(f"[×] Module: {module} not found.")
        # pass
        # print(f"[√] Module: {module} can be imported.")
        # else:
        # print(f"[×] Module: {module} not found.")
        return module_spec

    def get_protect_and_type(self):
        """
        :return: is Protect? and Protect name
        """
        for file in self.apk.get_files():
            if search(r".*\.so|db|jar|dat", file, flags=0):
                for so_name, so_r in soName.items():
                    if search(so_r, file, flags=0):
                        return True, so_name
        return False, ""

    def analyze(self):
        pass

    def get_danger_permission(self):
        return self.danger_permission

    def get_all_permission(self):
        return self.all_permission

    def show_certificate(self):
        pass
