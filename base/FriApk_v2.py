from re import search, findall
from common.PrintUtils import *
from androguard.core.bytecodes import apk
from androguard.core.androconf import *
from importlib import util, import_module
from common.protect import *
from common.adb import ADB
from common.docker_avd import AVD
from base import DEXDump
import threading

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

        self.vuln_obj = []

    def load_apk(self):
        if os.path.exists(self.apk_filename):
            if is_android(self.apk_filename) == "APK":
                self.apk = apk.APK(self.apk_filename, testzip=False)
                printGreen(f"[*] 是否有效APK")
                if self.apk.is_valid_APK():
                    print(f"\t[+] {self.apk.is_valid_APK()}")
                    self.all_permission = self.apk.get_permissions()
                    self.is_protect, self.protect_type = self.get_protect_and_type()

                    # self.show_apk_info()
                    self.emulator()
                    # self.load_modules()
                    # self.show_certificate()
            else:
                printRed("[!] File is not APK.")
        else:
            printRed("[!] No Found File.")

    def load_modules(self):
        for root, _, files in list(os.walk("module"))[1:]:
            root = root.replace("\\", "/")
            module_type = findall(r"module/(.*)", root)[0]
            if len(files):
                self.modules[module_type] = ['.'.join(['module', module_type, m[:-3]]) for m in files if
                                             m.endswith('py')]
        for module_type, modules in self.modules.items():
            for m in modules:
                if self.check_module(m):
                    m = import_module(m)
                    # try:
                    obj = m.Module(self.apk)
                    result = obj.run()
                    status = result['status']
                    if status:
                        module_res = result['result']
                        self.vuln_obj.append(module_res)
                        printGreen(f'[*] {module_res.name}')
                        print(f'{module_res.content}')
                        if module_res.poc:
                            printGreen("\t[+] POC")
                            print(module_res.poc+"\n")
                        if module_res.suggestion:
                            printGreen("\t[+] 修复建议:")
                            print(module_res.suggestion+"\n")
                    # except Exception as e:
                    #     print(f" [!] Load {m} Error.", e)
                    self.modules_load.append(m)

    def check_module(self, module):
        """
            check module is usability

        :param module: module name
        :return: module spec
        """

        print(f"[?] Check Module")
        module_spec = util.find_spec(module)
        # print(f"module_spec={module_spec}")
        if not module_spec: print(f"[×] Module: {module} not found.")
        # pass
        else:
            print(f"[√] Module: {module} can be imported.")
            print(f"[*] Loading {module} Module ...")
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

    def show_apk_info(self):
        printGreen(f"[*] 应用基本信息")
        print(f"""\t应用名称: {self.apk.get_app_name()}
        包名: {self.apk.get_package()}
        加固: {self.protect_type if self.is_protect else "未加固"}
        大小: {os.path.getsize(self.apk.filename)} Bytes
        MainActivity: {self.apk.get_main_activity()}
        """)

    def emulator(self):
        a1 = AVD()
        a1.new_avd()
        port_list = a1.get_mapping_port(a1.container_id)
        for port in port_list:
            adb = ADB()
            status, res = adb.connect_network("0.0.0.0", port)
            if status: break
        print(res)
        print("hahahah")
        # device = adb.get_devices()[0]
        # adb.set_device(device)
        # adb.install(self.apk_filename, device)
        # adb.start_app(device, self.apk.get_package(), self.apk.get_main_activity())
        # _ = adb.start_frida_server()  # 启动frida-server 会返回一个线程对象
        # f = DEXDump.dumpDex()


