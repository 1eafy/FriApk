from os.path import exists
import re
from config.config import ADB_PATH, FRIDA_SERVER_PATH
from common.Utils import command

import threading


class ADB:
    def __init__(self):
        self.adb = ADB_PATH
        self.devices = []
        self.package = ""
        self.SIGSTOP = True
        #if self._exists_adb():
        #    res = command(f"{ADB_PATH} devices", encoding="gbk")
        #    self.devices = re.findall("(.*)\sdevice\s", res)
        #else:
        #    raise FileNotFoundError

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

    def install(self, apk_path, device):
        """
        install apk on Specified device
        :param apk_path:
        :param device:
        :return:
        """

        res = command(f"{self.adb} -s {device} install {apk_path}", encoding="gbk")
        print(res)

    def connect_network(self, ip, port='5555'):
        res = command(f"{self.adb} connect {ip}:{port}")
        self.device = ip + ":" + port
        return "cannot" not in res, res

    def start_app(self, device, package, mainActivity):
        self.package = package
        res = command(f"{self.adb} -s {device} shell am start -n {package}/{mainActivity}", encoding="gbk")
        print(res)

    def set_device(self, device):
        self.device = device

    def start_frida_server(self, frida=FRIDA_SERVER_PATH):
        # 开一个线程启动frida-server
        print('启动Frida')
        thread = threading.Thread(target=command, args=(f"{self.adb} shell {frida}",))
        thread.start()
        # thread.join()

    def kill_server(self):
        res = command(f"{self.adb} kill-server")
        print(res)

    def adb_shell(self, cmd, device):
        res = command(f"{self.adb} {cmd}")
        return res


    def push(self, src_path, dst_path):
        pass


    # def __del__(self):
    #     print('卸载App')
    #     # res = command(f"{self.adb} -s {self.device} uninstall {self.package}")
    #     # print(res)

# if __name__ == '__main__':
#     apk = r"C:\Users\acer\Desktop\testApk\轻启动_2.15.0.apk"
#     adb = ADB()
#     devices = adb.get_devices()
#     d = devices[1]
#     adb.install(apk, d)
