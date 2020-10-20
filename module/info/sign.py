from asn1crypto import x509
from common.Vulnerability import *
from libs.androguard.core.bytecodes import apk
import binascii
from oscrypto import asymmetric



class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name" : "Application certificate info",
            "Author" : "xxx",
            "Description" : "获取应用签名证书信息.代码摘抄: androguard.cli.main -> androsign_main",
        }
        self.status = False

    def run(self):
        from libs.androguard.util import get_certificate_name_string
        certs = set(self.apk.get_certificates_der_v2() + self.apk.get_certificates_der_v3() +
                    [self.apk.get_certificate_der(x) for x in self.apk.get_signature_names()])
        pkeys = set(self.apk.get_public_keys_der_v2() + self.apk.get_public_keys_der_v3())

        for cert in certs:
            x509_cert = x509.Certificate.load(cert)
            print('Issuer:', get_certificate_name_string(x509_cert.issuer))
            print('Subject:', get_certificate_name_string(x509_cert.subject))
            print('Serial Number:', hex(x509_cert.serial_number)[2:].upper())
            print('Hash Algorithm:', x509_cert.hash_algo.upper())
            print('Signature Algorithm:', x509_cert.signature_algo.upper())
            print('Valid not before:', x509_cert['tbs_certificate']['validity']['not_before'].native)
            print('Valid not after:', x509_cert['tbs_certificate']['validity']['not_after'].native)

        print()

        for public_key in pkeys:
            x509_public_key = asymmetric.load_public_key(public_key)
            # x509_public_key = keys.PublicKeyInfo.load(public_key)
            # x = asymmetric.PublicKey(public_key, x509_public_key)
            print('PublicKey Algorithm:', x509_public_key.algorithm)
            print('Bit Size:', x509_public_key.bit_size)
            print('Fingerprint:', binascii.hexlify(x509_public_key.fingerprint).decode('utf-8'))
            try:
                print('Hash Algorithm:', x509_public_key.hash_algo)
            except Exception:
                # RSA pkey does not have an hash algorithm
                pass