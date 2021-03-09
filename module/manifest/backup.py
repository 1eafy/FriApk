# from libs.androguard.core.bytecodes import apk as aaa
# from libs.androguard.core.bytecodes.dvm import *
# from asn1crypto import x509, keys
from common.Vulnerability import *
from common.PrintUtils import *

class Module:
    def __init__(self, apk, decomplier):
        self.apk = apk
        self.decomplier = decomplier
        self.module_info = {
            "Name": "应用备份",
            "Author": "xxx",
            "Date": "2020.10.20",
            "Description": "Android API Level 8及其以上Android系统提供了为应用程序数据的备份和恢复功能，此功能的开关决定于该应用程序中AndroidManifest.xml文件中的allowBackup属性值[1] ，其属性值默认是true。当allowBackup标志为true时，用户即可通过adb backup和adb restore来进行对应用数据的备份和恢复，这可能会带来一定的安全风险。",
            "Reference": [
                "https://segmentfault.com/a/1190000002590577",
            ],
        }

        self.status = False
        # dex = self.apk.get_dex()
        # dex_name = self.apk.get_dex_names()
        # 返回一个filter对象,
        # filter() 函数用于过滤序列,过滤掉不符合条件的元素,返回由符合条件元素组成的新列表
        # for d in dex_name:
        #     print(d)
        # print('multi dex')
        # for dex in self.apk.get_all_dex():
        #     dv = DalvikVMFormat(dex)
        #     for s in dv.get_strings():
        #         print(s)
        # dv = DalvikVMFormat(self.apk.get_dex())
        # for i in dv.get_classes_names():
        #     print(i)
#         print(self.apk.is_signed())
#         print("APK is signed with: {}".format("v1 and v2" if self.apk.is_signed_v1() and
#                                                         self.apk.is_signed_v2() else "v1" if self.apk.is_signed_v1() else "v2"))
#
#         for cert in self.apk.get_certificates():
#             cert_sha256 = cert.sha256_fingerprint.replace(" ",":")
#             cert_sha1 = cert.sha1_fingerprint.replace(" ",":")
#             print(f"""
# sha1:    {cert_sha1}
# sha256:  {cert_sha256}
#             """)
#             print(cert.issuer.human_friendly) # 发布者
#             print(cert.subject.human_friendly)  # 所有者
#             # print(cert.issuer_serial)
#             print(cert.hash_algo) # 签名算法
#             print(cert.signature_algo) # 签名算法
#             print(hex(cert.serial_number)[2:]) # 序列化, 属性值为十进制，需转为hex()转为十六进制，去除'0x'
#             print('----------')
            # print('\n'.join(['{}:{}'.format(item for item in cert.__dict__.items())]))
            # for k, v in cert.__dict__.items():
            #     print(k, v)

    def run(self):

        allow_backup = self.apk.get_attribute_value("application", "allowBackup")
        # allow_debug = self.apk.get_attribute_value("application", "debuggable")
        data = {
            'backup':{
                'title': self.module_info['Name'],
                'allow_backup': [],
                'res': True,
                'suggestion': [],
                'desc': self.module_info['Description'],

            }


        }
        level = INFO
        content = f"\t{allow_backup}"
        poc = ""
        poc1 = ""
        suggestion = ""
        suggestion1 = ""

        if allow_backup and allow_backup.lower() == "true":
            level = HIGH
            self.status = True
            suggestion = f"\t{RED}设置AndroidManifest.xml的allowBackup标志为false{END}"
            poc = f"""{RED}
                    BackupPOC:
                        >>> adb backup -f back.ab -noapk {self.apk.get_package()}
                    Install App on other Phone.
                    RecoveryPOC:
                        >>> adb restore back.ab{END}"""

            poc1 ="""BackupPOC:
    >>> adb backup -f back.ab -noapk {self.apk.get_package()}
Install App on other Phone.
RecoveryPOC:
    >>> adb restore back.ab"""
            suggestion1 = "设置AndroidManifest.xml的allowBackup标志为false"



        data['backup']['level'] = level
        data['backup']['suggestion'].append(suggestion1)
        data['backup']['poc'] = poc1
        data['backup']['res'] = self.status
        self.status = True
        vuln = Vulnerable(name=self.module_info['Name'],
                          level=level,
                          content=content,
                          poc=poc,
                          suggestion=suggestion,
                          data=data,
                          )

        return {
            "status": self.status,
            'result': vuln
        }
        # print("Check backup")

