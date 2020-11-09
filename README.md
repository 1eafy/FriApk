# FriApk
> 基于Frida、Androguard，联动Android emulator脱壳，进行静态、动态漏洞检测工具，非法获取用户设备、敏感信息行为检测（猜想）

### requirements.txt
```
networkx == 2.5
asn1crypto == 1.4.0
frida == 12.11.18
colorama == 0.4.3
lxml == 4.4.1
click == 7.1.2
```
pip安装frida的时候耗时比较长 请耐心等待
###### **注: frida版本与模拟器的frida-server版本尽量需要对应上**
# 参考
- [Androguard](https://github.com/androguard/androguard)
- [apkscanner](https://github.com/gremwell/apkscanner)
- [AndroidChecklist](https://github.com/guanchao/AndroidChecklist)
- [AndroidSecurityStudy](https://github.com/r0ysue/AndroidSecurityStudy)
- [Android软件安全与逆向分析](https://bbs.pediy.com/forum-168.htm)
- ...

Blog: [https://icheung.net](https://icheung.net)

问题
1. Apk路径不能有空格
