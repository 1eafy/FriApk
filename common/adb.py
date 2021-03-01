from os.path import exists
import re
from config.config import ADB_PATH, FRIDA_SERVER_PATH
from common.Utils import command
import frida

import threading


class ADB:
    def __init__(self):
        self.adb = ADB_PATH
        self.devices = []
        self.package = ""
        self.SIGSTOP = True
        self.device = ""
        if self._exists_adb():
           res = command(f"{ADB_PATH} devices", encoding="gbk")
           self.devices = re.findall("(.*)\sdevice\s", res)
           p_list = command(f"{ADB_PATH} shell pm list package", encoding='gbk')
           self.package_list = re.findall('package:(.*)\r', p_list)
        else:
           raise FileNotFoundError

    def _exists_adb(self):
        """
        :return:
        """
        return exists(self.adb)

    def get_devices(self):
        """
        get devices
        :return: Devices list
        """
        return self.devices

    def install(self, apk_path, package_name):
        """
        install apk on Specified device
        :param apk_path:
        :param package_name:
        :return:
        """
        try:
            self.package = package_name
            if package_name in self.package_list:
                print('[!] 软件已存在该设备, 跳过安装')
                return True
            c = f"{self.adb} -s {self.device} install {apk_path}"
            res = command(c, encoding="gbk")
            return 'Success' in res
        except Exception:
            print(Exception)



    def connect_network(self, ip, port='5555'):
        res = command(f"{self.adb} connect {ip}:{port}")
        self.device = ip + ":" + port
        return "cannot" not in res, res

    def start_app(self, device, mainActivity):
        res = command(f"{self.adb} -s {device} shell am start -n {self.package}/{mainActivity}", encoding="gbk")
        print(res)

    def set_device(self, device):
        self.device = device

    def start_frida_server(self, frida=FRIDA_SERVER_PATH):
        print('启动frida-server')
        command(f'{self.adb} -s {self.device} shell "su -c {frida}"', read_rev=False)

    def kill_server(self):
        res = command(f"{self.adb} kill-server")
        print(res)

    def adb_shell(self, cmd, device=None):
        res = command(f"{self.adb} {cmd}")
        return res

    def check_frida_server(self):
        try:
            frida.get_usb_device()
            return True
        except Exception:
            return False


    def push(self, src_path, dst_path):
        pass


    def __del__(self):
        if self.package:
            print('卸载App')
            res = command(f"{self.adb} -s {self.device} uninstall {self.package}")
            print(res)
        # print('kill-server')
        # res = command(f"{self.adb} kill-server")
        # print(res)

# if __name__ == '__main__':
#     apk = r"C:\Users\acer\Desktop\testApk\轻启动_2.15.0.apk"
#     adb = ADB()
#     devices = adb.get_devices()
#     d = devices[1]
#     adb.install(apk, d)
