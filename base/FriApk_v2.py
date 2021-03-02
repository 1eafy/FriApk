from re import search, findall
from common.PrintUtils import *
from androguard.core.bytecodes import apk
from androguard.core.androconf import *
from importlib import util, import_module
from common.protect import *
from common.adb import ADB
from config.config import BASE_PATH, WEB_ROOT_DIR
from common.dexdump.main import entry
import imgkit

class FriApk:
    def __init__(self, apk, uid=None):
        # self.apk_filename = args.apk
        self.apk_filename = apk
        self.apk = None
        self.uid = uid
        self.all_permission = []
        self.danger_permission = []
        self.modules = {}
        self.modules_load = []
        self.report_data = {}
        self.dx = None
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
                    k, v = self.show_apk_info().popitem()
                    self.report_data[k] = v

                    if self.is_protect:
                        pass
                        # self.emulator()
                        # dx = self.init_Dv()
                    self.load_modules()

                    # self.show_certificate()
                    self.save_icon()
                    return {'code': True, 'data': self.report_data}
            else:
                printRed("[!] File is not APK.")
                return {'code': False, 'msg': "Invalid Apk"}
        else:
            printRed("[!] No Found File.")
            return {'code': False, 'msg': "Apk 404"}

    def save_icon(self):
        # f"{WEB_ROOT_DIR}{os.sep}report{os.sep}{self.uid}.png"
        # with open(os.path.join(WEB_ROOT_DIR, 'report', f'{self.uid}.png'), 'wb') as f:
        icon_save_path = os.path.join(WEB_ROOT_DIR, 'static', f'{self.uid}.png')
        icon_path =self.apk.get_app_icon()
        if 'xml' in icon_path:
            self.report_data['icon'] = False
        else:
            self.report_data['icon'] = True
            with open(icon_save_path, 'wb') as f:
                f.write(self.apk.get_file(icon_path))

    def init_Dv(self):
        from androguard.core.bytecodes import dvm
        from androguard.decompiler.dad.decompile import DvMethod
        from androguard.core.analysis.analysis import Analysis
        from androguard.core.analysis import analysis
        from pprint import pprint as pp
        from androguard.decompiler.decompiler import DecompilerJADX
        from config.config import JADX_PATH
        from config.config import DEX_SAVE_PATH
        from common.fix_v1 import fix_dex_header

        dx = Analysis()
        # for dex in self.apk.get_all_dex():
        #     d = dvm.DalvikVMFormat(dex)
        #     dx.add(d)

        for root, dir_name, file_list in os.walk(os.path.join(DEX_SAVE_PATH, self.apk.get_package())):
            for f in file_list:
                fix_dex_header(os.path.join(root, f))
                print(os.path.join(root, f))
                with open(os.path.join(root, f), 'rb') as file:
                    try:
                        d = dvm.DalvikVMFormat(file.read())
                        dx.add(d)
                    except Exception:
                        printRed("[ERROR] {}".format(os.path.join(root, f)))

                    # for i in dx.get_classes():
                    #     print(i)
        self.dx = dx


    def load_modules(self):
        os.chdir(BASE_PATH)
        for root, _, files in list(os.walk("module"))[1:]:
            root = root.replace("\\", os.path.sep).replace("/", os.path.sep)
            module_type = findall("module/|\\\(.*)", root)[0]
            if len(files):
                self.modules[module_type] = ['.'.join(['module', module_type, m[:-3]]) for m in files if
                                             m.endswith('py')]
        for module_type, modules in self.modules.items():
            # print(module_type)
            # print(modules)
            # print('-' * 10)
            for module in modules:
                if self.check_module(module):
                    m = import_module(module)
                    # try:
                    obj = m.Module(self.apk)
                    result = obj.run()
                    status = result['status']
                    if status:
                        module_res = result['result']
                        k, v = module_res.data.popitem()
                        self.report_data[k] = v

                        self.vuln_obj.append(module_res)
                        printGreen(f'[*] {module_res.name}')
                        print(f'{module_res.content}')
                        if module_res.poc:
                            printGreen("\t[+] POC")
                            print(module_res.poc + "\n")
                        if module_res.suggestion:
                            printGreen("\t[+] 修复建议:")
                            print(module_res.suggestion + "\n")
                    # except Exception as e:
                    #     print(f" [!] Load {m} Error.", e)
                    self.modules_load.append(m)


    def check_module(self, module):
        """
            check module is usability

        :param module: module name
        :return: module spec
        """

        # print(f"[?] Check Module")
        module_spec = util.find_spec(module)
        # print(f"module_spec={module_spec}")
        if not module_spec:
            print(f"[×] Module: {module} not found.")
        # pass
        else:
            pass
            # print(f"[√] Module: {module} can be imported.")
            # print(f"[*] Loading {module} Module ...")
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
        data = {

            'apk_info': {
                'title': "应用基本信息",
                'name': self.apk.get_app_name(),
                'package': self.apk.get_package(),
                'version': self.apk.get_androidversion_name(),
                'protect': self.protect_type if self.is_protect else "未加固",
                'size': os.path.getsize(self.apk.filename),
                'MainActivity': self.apk.get_main_activity(),
                'MD5': self.get_apk_md5(),
                'sign': True if self.apk.get_signature() else False,
                'res': True
            },

        }
        printGreen(f"[*] 应用基本信息")
        print(f"""\t应用名称: {self.apk.get_app_name()}
        包名: {self.apk.get_package()}
        加固: {self.protect_type if self.is_protect else "未加固"}
        大小: {os.path.getsize(self.apk.filename)} Bytes
        MainActivity: {self.apk.get_main_activity()}
        """)
        return data

    def get_apk_md5(self):
        from hashlib import md5
        o = md5()
        buff = 512
        size = os.path.getsize(self.apk_filename)
        with open(self.apk_filename, 'rb') as f:
            while size > buff:
                o.update(f.read(buff))
                size -= buff
            o.update(f.read(size))
            v = o.hexdigest().upper()
        return v

    def emulator(self):
        adb = ADB()
        print('[+] 该应用存在加固, 正在尝试脱壳.')
        print('[+] 请启动安卓模拟器, 程序尝试自动启动Frida-server守护进程')
        input('[*] 准备完成请按回车键: ')
        devices = adb.get_devices()
        device_num = 0
        if len(devices) > 1:
            for i, d in enumerate(devices): print(f"{i}. {d}")
            device_num = input('[!] 存在多个设备, 请选择: ').strip()
        # print(type(device_num), device_num)
        try:
            device = devices[int(device_num)]
        except Exception:
            printRed('[!] 输入有误! 自动退出.')
            exit(1)
        adb.set_device(device)
        adb.start_frida_server()
        # exit(1)
        frida_server_status = adb.check_frida_server()
        if frida_server_status:
            print('[+] Frida-server 启动成功')
            print('[INFO] 正在安装应用...')
            if adb.install(self.apk_filename, self.apk.get_package()):
                print('[+] 安装成功')
                print('[INFO] 尝试脱壳...')
                adb.package = self.apk.get_package()
                print("包名: ", adb.package)
                entry(process=self.apk.get_package(), enable_spawn_mode=True, delay_second=5)
