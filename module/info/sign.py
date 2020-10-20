from asn1crypto import x509
from common.Vulnerability import *
from libs.androguard.core.bytecodes import apk
import binascii
from re import findall


class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "Application certificate Info",
            "Author": "xxx",
            "Date": "",
            "Description": "获取应用签名证书信息.",
            "Reference": [
                "https://github.com/androguard/androguard/blob/master/androguard/cli/main.py.androsign_main",

            ],
        }
        self.status = False

    def run(self):

        result = []

        # 判断有无签名，无签名返回None
        if self.apk.get_signature():
            from libs.androguard.util import get_certificate_name_string
            certs = set(self.apk.get_certificates_der_v2() + self.apk.get_certificates_der_v3() +
                        [self.apk.get_certificate_der(x) for x in self.apk.get_signature_names()])
            pkeys = set(self.apk.get_public_keys_der_v2() + self.apk.get_public_keys_der_v3())

            result.append('\tAPK is signed with: {}'.format(
                "v1 and v2" if self.apk.is_signed_v1() and self.apk.is_signed_v2() else "v1" if self.apk.is_signed_v1()
                                                                                            else "v2"))

            for cert in certs:
                x509_cert = x509.Certificate.load(cert)
                result.append('\tIssuer:{}'.format(get_certificate_name_string(x509_cert.issuer)))
                result.append('\tSubject: {}'.format(get_certificate_name_string(x509_cert.subject)))
                result.append('\t序列号: {}'.format(hex(x509_cert.serial_number)[2:].upper()))
                result.append('\tHash Algorithm: {}'.format(x509_cert.hash_algo.upper()))
                result.append('\t\tSHA1: {}'.format(x509_cert.sha1_fingerprint.replace(" ", ":")))
                result.append('\t\tSHA256: {}'.format(x509_cert.sha256_fingerprint.replace(" ", ":")))
                result.append('\tSignature Algorithm: {}'.format(x509_cert.signature_algo.upper()))
                result.append('\t有效期为: {} 至 {}'.format(x509_cert['tbs_certificate']['validity']['not_before'].native,
                                                       x509_cert['tbs_certificate']['validity']['not_after'].native))
                # result.append('\tValid not after:'.format(x509_cert['tbs_certificate']['validity']['not_after'].native))

            from oscrypto import asymmetric
            for public_key in pkeys:
                x509_public_key = asymmetric.load_public_key(public_key)
                # x509_public_key = keys.PublicKeyInfo.load(public_key)
                # x = asymmetric.PublicKey(public_key, x509_public_key)
                result.append('\tPublicKey Algorithm: {} Bit {} '.format(x509_public_key.bit_size,
                                                                         x509_public_key.algorithm.upper()))
                result.append('\tBit Size: {}'.format(x509_public_key.bit_size))
                pub_fg = binascii.hexlify(x509_public_key.fingerprint).decode('utf-8').upper()
                tmp = findall('.{2}', pub_fg)  # 指定长度分割字符串
                pub_fg = ':'.join(tmp)
                result.append('\tPublic Fingerprint: {}'.format(pub_fg))
                try:
                    result.append('\tHash Algorithm: {}'.format(x509_public_key.hash_algo))
                except Exception:
                    # RSA pkey does not have an hash algorithm
                    pass
                    # print("No Hash Algorithm.")

            self.status = True
        else:
            result.append('\t无签名.')

        vuln = Vulnerable(self.module_info['Name'],
                          INFO,
                          content='\n'.join(result),
                          )

        return {
            "status": self.status,
            'result': vuln
        }
