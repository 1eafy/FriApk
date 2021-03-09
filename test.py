import frida
import os

# d = frida.get_usb_device()
# app = d.enumerate_applications()    # 枚举已安装的应用
# p = d.enumerate_processes()     # 枚举进程
#
# print(p)
from jinja2 import PackageLoader,Environment

n = os.getcwd()
a = os.path.join(n, '../')
f = os.path.join(a, 'Volun.py')
with open(f, 'r') as f:
    print(f.read())
print(os.path.exists(os.path.join(a, 'Volun.py')))
print(a)