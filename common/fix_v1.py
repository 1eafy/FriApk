import binascii
from struct import pack, unpack
from hashlib import sha1
from zlib import adler32


def fix_dex_header(dex_file):
    with open(dex_file, 'r+b') as f:
        try:
            # _fix_signature(f)
            _fix_adler32(f)
        except Exception as e:
            print('[ERROR] FIX DEX HEADER ERROR. ', e)


def _fix_signature(file):
    print('[INFO] Check Signature...')
    file.seek(0xc)
    sha_1 = sha1()
    src_sign = file.read(20)
    src_sign = b2a(src_sign)

    # 开始计算signature
    file.seek(0x20)  # 0x20 == 32 == dex.035(8 bytes) + checksum(4 bytes) + signature(20 bytes)
    content = file.read(1024)
    while content:
        sha_1.update(content)
        content = file.read(1024)
    correct_sign = sha_1.hexdigest()

    print('src_sign >> ', src_sign)
    print('correct_sign >> ', correct_sign)

    if correct_sign == src_sign:
        print('[INFO] signature is correct.')
    else:
        print('[INFO] signature is wrong.')
        print('[INFO] Modify signature.')
        file.seek(0xc)
        file.write(bytes.fromhex(correct_sign))
        print('[INFO] Modify succeeded.')



def _fix_adler32(file):
    print('[INFO] Check Adler32...')
    file.seek(8)
    src_adler32 = file.read(4)
    # src_adler32 = b2a(src_adler32)
    # print(src_adler32)
    # tmp = bytearray(src_adler32)
    # tmp.reverse()
    # src_adler32 = bytes(tmp)
    src_adler32 = b2a(src_adler32)

    # 计算 adler32
    content = file.read(1024)
    correct_adler32 = 1
    while content:
        correct_adler32 = adler32(content, correct_adler32)
        content = file.read(1024)
    correct_adler32 = correct_adler32 & 0xffffffff # & 0xffffffff 为了适应各平台Python与系统


    correct_adler32 = pack('<I', correct_adler32) # 小端序
    correct_adler32_str = b2a(correct_adler32)
    print('src_adler32     >> ', src_adler32)
    print('correct_adler32 >>', correct_adler32_str)
    if src_adler32 == correct_adler32_str:
        print('[INFO] Adler32 same.')
    else:
        print('[INFO] Adler32 is not same.')
        file.seek(8)
        file.write(correct_adler32)
        print('[INFO] Modify succeeded.')




def b2a(b):
    t = binascii.b2a_hex(b)
    return str(t, encoding='utf-8').upper()

if __name__ == '__main__':
    fix_dex_header("0x9addd000.dex")