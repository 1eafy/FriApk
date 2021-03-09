from asn1crypto import x509
from common.Vulnerability import *
import binascii
from re import findall

"""
从Android 7.0开始, 谷歌增加新签名方案 V2 Scheme (APK Signature);
但Android 7.0以下版本, 只能用旧签名方案 V1 scheme (JAR signing)

v1签名是对jar进行签名，V2签名是对整个apk签名：
    官方介绍就是：v2签名是在整个APK文件的二进制内容上计算和验证的，v1是在归档文件中解压缩文件内容。

二者签名所产生的结果：
v1：在v1中只对未压缩的文件内容进行了验证，所以在APK签名之后可以进行很多修改——文件可以移动，甚至可以重新压缩。
    即可以对签名后的文件在进行处理
v2：v2签名验证了归档中的所有字节，而不是单独的ZIP条目，如果您在构建过程中有任何定制任务，
    包括篡改或处理APK文件，请确保禁用它们，否则您可能会使v2签名失效，从而使您的APKs与Android 7.0和以上版本不兼容。
"""


class Module:
    def __init__(self, apk, decomplier):
        self.apk = apk
        self.decomplier = decomplier
        self.module_info = {
            "Name": "Application Certificate Info",
            "Author": "xxx",
            "Date": "",
            "Description": "获取应用签名证书信息.",
            "Reference": [
                "https://github.com/androguard/androguard/blob/master/androguard/cli/main.py.androsign_main",

            ],
        }
        self.status = True

    def run(self):

        result = []
        data = {

            'cert_info': {
                'title': self.module_info['Name'],
                'res': True,
                'field': {}
            },

        }

        # 判断有无签名，无签名返回None
        if self.apk.get_signature():
            from androguard.util import get_certificate_name_string
            certs = set(self.apk.get_certificates_der_v2() + self.apk.get_certificates_der_v3() +
                        [self.apk.get_certificate_der(x) for x in self.apk.get_signature_names()])
            pkeys = set(self.apk.get_public_keys_der_v2() + self.apk.get_public_keys_der_v3())

            signed_v = "v1 and v2" if self.apk.is_signed_v1() and self.apk.is_signed_v2() else "v1" if self.apk.is_signed_v1() else "v2"
            result.append('\tAPK is signed with: {}'.format(signed_v))

            data['cert_info']['field']['signed_v'] = signed_v

            for cert in certs:
                x509_cert = x509.Certificate.load(cert)
                data['cert_info']['field']['issuer'] = get_certificate_name_string(x509_cert.issuer)
                result.append('\tIssuer: {}'.format(data['cert_info']['field']['issuer']))
                data['cert_info']['field']['subject'] = get_certificate_name_string(x509_cert.subject)
                result.append('\tSubject: {}'.format(get_certificate_name_string(x509_cert.subject)))
                data['cert_info']['field']['serial'] = hex(x509_cert.serial_number)[2:].upper()
                result.append('\t序列号: {}'.format(hex(x509_cert.serial_number)[2:].upper()))
                data['cert_info']['field']['hash_algo'] = x509_cert.hash_algo.upper()
                result.append('\tHash Algorithm: {}'.format(x509_cert.hash_algo.upper()))
                data['cert_info']['field']['sha1_fingerprint'] = x509_cert.sha1_fingerprint.replace(" ", ":")
                result.append('\t\tSHA1: {}'.format(x509_cert.sha1_fingerprint.replace(" ", ":")))
                data['cert_info']['field']['sha256_fingerprint'] = x509_cert.sha256_fingerprint.replace(" ", ":")
                result.append('\t\tSHA256: {}'.format(x509_cert.sha256_fingerprint.replace(" ", ":")))
                data['cert_info']['field']['signature_algo'] = x509_cert.signature_algo.upper()
                result.append('\tSignature Algorithm: {}'.format(x509_cert.signature_algo.upper()))
                data['cert_info']['field']['no_before'] = x509_cert['tbs_certificate']['validity']['not_before'].native
                data['cert_info']['field']['no_after'] = x509_cert['tbs_certificate']['validity']['not_after'].native
                result.append('\t有效期为: {} 至 {}'.format(x509_cert['tbs_certificate']['validity']['not_before'].native,
                                                       x509_cert['tbs_certificate']['validity']['not_after'].native))
                # result.append('\tValid not after:'.format(x509_cert['tbs_certificate']['validity']['not_after'].native))

            from oscrypto import asymmetric
            for public_key in pkeys:
                x509_public_key = asymmetric.load_public_key(public_key)
                # x509_public_key = keys.PublicKeyInfo.load(public_key)
                # x = asymmetric.PublicKey(public_key, x509_public_key)
                data['cert_info']['field']['bit_size'] = x509_public_key.bit_size
                data['cert_info']['field']['algorithm'] = x509_public_key.algorithm.upper()
                result.append('\tPublicKey Algorithm: {} Bit {} '.format(x509_public_key.bit_size,
                                                                         x509_public_key.algorithm.upper()))
                result.append('\tBit Size: {}'.format(x509_public_key.bit_size))
                pub_fg = binascii.hexlify(x509_public_key.fingerprint).decode('utf-8').upper()
                tmp = findall('.{2}', pub_fg)  # 指定长度分割字符串
                pub_fg = ':'.join(tmp)
                data['cert_info']['field']['Public_Fingerprint'] = pub_fg
                result.append('\tPublic Fingerprint: {}'.format(pub_fg))
                try:
                    data['cert_info']['field']['hash_algorithm'] = x509_public_key.hash_algo
                    result.append('\tHash Algorithm: {}'.format(x509_public_key.hash_algo))
                except Exception:
                    # RSA pkey does not have an hash algorithm
                    pass
                    # print("No Hash Algorithm.")

            self.status = True
            data['cert_info']['res'] = True
        else:
            self.status = True
            data['cert_info']['res'] = False
            result.append('\t无签名.')

        vuln = Vulnerable(self.module_info['Name'],
                          INFO,
                          content='\n'.join(result),
                          data=data,
                          )

        return {
            "status": self.status,
            'result': vuln
        }
