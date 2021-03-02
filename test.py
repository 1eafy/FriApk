import frida

# d = frida.get_usb_device()
# app = d.enumerate_applications()    # 枚举已安装的应用
# p = d.enumerate_processes()     # 枚举进程
#
# print(p)
from jinja2 import PackageLoader,Environment
d = {"a":1,"b":2}
l = ["sdfa",2,3,4,4]
for k, v in l:
    print(k, v)
