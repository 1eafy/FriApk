import os
import zipfile
from re import search
from common.PrintUtils import *
from common.Utils import *

from common.protect import *
from config.config import *
from xml.etree import ElementTree as ET


NS = "{http://schemas.android.com/apk/res/android}"


class FriApk:
    def __init__(self, args):
        self.apk = args.apk
        self.apkPath = os.path.split(self.apk)[0]
        self.isProtect = False
        self.manifestPath = None
        self.apkFile = None
        self.root = None
        self.MainActivity = ""
        self.apkVersionInfo = {
            "versionCode": "",
            "versionName": "",
            "compileSdkVersion": "",
            "compileSdkVersionCodename": "",
            "package": "",
            "platformBuildVersionName": "",
            "platformBuildVersionCode": "",
        }
        self.apkPermission = {

        }
        self.allow_exported_list = []
        # self.load_apk()

        # print(markName)

    def permission(self):
        self.decompile_manifest()
        try:
            ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
            manifest = ET.ElementTree(file=self.manifestPath)
            self.root = manifest.getroot()
        except Exception as e:
            print("ERROR Parse AndroidManifest.xml ", e)
            return
        package = self.root.get("package")
        printGreen(f"[*]获取包名")
        print(f"\t[+]{package}")
        printGreen("[*]解析权限")
        for v in self.apkVersionInfo.keys():
            self.apkVersionInfo[v] = self.root.get(v) if self.root.get(v, None) else self.root.get(f'{NS}{v}')
        # print(self.apkVersionInfo)
        for child in self.root:
            if child.tag == "uses-permission":
                permission_name = child.attrib[f"{NS}name"]
                permission_description = allPermission[permission_name] if allPermission.get(permission_name,
                                                                                             None) else {
                    "description": "应用程序自定义权限",
                    "level": "N"
                }
                if permission_description['level'] == "D":
                    printRed(f'\t[+]{permission_name} : {permission_description["description"]}')
                else:
                    print(f'\t[+]{permission_name} : {permission_description["description"]}')

        self.get_main_activity()

    def get_main_activity(self):
        printGreen("[*]获取MainActivity")
        for child in self.root:
            if child.tag == "application":
                for appChild in list(child):
                    if appChild.tag == "activity":
                        if appChild.get(f'{NS}exported', "false").lower() == 'true': self.allow_exported_list.append(
                            appChild.get(f"{NS}name"))
                        for i in list(appChild):
                            for j in i:
                                if j.tag == "action" and j.attrib[f'{NS}name'] == "android.intent.action.MAIN":
                                    m = appChild.attrib[f'{NS}name']
                                    self.MainActivity = m


    def load_apk(self):
        if not os.path.isfile(self.apk):
            print("File does not exist")
            exit(0)
        if not os.path.split(self.apk)[1].endswith('apk'):
            print("No Apk!")
            exit(0)
        try:
            self.apkFile = zipfile.ZipFile(self.apk)
            self.apkFile.extract("AndroidManifest.xml", self.apkPath)
        except Exception as e:
            print("extract AndroidManifest.xml error,", e)
            return
        finally:
            self.apkFile.close()
        self.get_sign_info()
        self.get_protect_type()
        self.permission()
        self.allow_backup()
        self.allow_debuggable()
        self.get_uses_sdk()

    def get_protect_type(self):
        printGreen("[*]获取加固类型")
        for file in self.apkFile.namelist():
            if search(r".*\.so|db|jar|dat", file, flags=0):
                for so_name, so_r in soName.items():
                    if search(so_r, file, flags=0):
                        self.isProtect = True
                        print(f"\t[+]{so_name}")
                        # return
                        # break
                # 跳出二层For循环方法
                # 只有当for正常结束的时候才会执行else语句
                # else:
                #     continue
                # break
        print(f"\t[-]未加固")

    def decompile_manifest(self):
        self.manifestPath = os.path.join(self.apkPath, "AndroidManifest.xml")
        try:
            manifest_content = command(f"java -jar {TOOLS_PATH}\\AXMLPrinter2.jar {self.manifestPath}")
        except Exception as e:
            print("Decompile AndroidManifest Error", e)
            return

        with open(self.manifestPath, 'w', encoding='utf-8') as f:
            f.write(manifest_content)

    def get_sign_info(self):
        printGreen(f"[*]获取签名信息")
        try:
            sign_content = command(f"keytool.exe -printcert -jarfile {self.apk}", "gbk")
            print(sign_content)
        except Exception as e:
            print("获取签名信息失败.", e)

    def allow_backup(self):
        printGreen("[*]allowBackup")
        for child in self.root:
            if child.tag == "application":
                is_allow = child.get(f"{NS}allowBackup", False)
                if is_allow == "true":
                    printRed(f"\t[+]该应用程序允许备份")
                else:
                    print(f"\t[+]该应用程序不允许备份")
                break

    def allow_debuggable(self):
        printGreen("[*]allowDebugger")
        for child in self.root:
            if child.tag == "application":
                is_allow = child.get(f"{NS}debuggable", False)
                if is_allow == "true":
                    printRed(f"\t[+]该应用程序允许调试")
                else:
                    print(f"\t[+]该应用程序不允许调试")
                return

    def get_uses_sdk(self):
        printGreen("[*]uses-sdk")
        for child in self.root:
            if child.tag == "uses-sdk":
                minSdkVersion = child.get(f"{NS}minSdkVersion", None)
                targetSdkVersion = child.get(f"{NS}targetSdkVersion", None)
                print(f"\t[+]minSdkVersion = {minSdkVersion}")
                print(f"\t[+]targetSdkVersion = {targetSdkVersion}")
                return
