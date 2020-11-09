from os.path import *
from os import *

TOOLS_PATH = join(getcwd(), 'libs')

# 项目根目录
BASE_PATH = dirname(dirname(abspath(__file__)))

# 反编译工具Jadx绝对路径
JADX_PATH = normcase(join(BASE_PATH, "libs/jadx-1.1.0/bin/jadx.bat")).replace("\\", sep)

# Linux ADB绝对路径
# ADB_PATH = "adb"

# Windows ADB路径
ADB_PATH = normcase(join(BASE_PATH, "libs/adb.exe")).replace("\\", sep)

# Frida-server在模拟器中的绝对路径
FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
# FRIDA_SERVER_PATH = "/data/local/tmp/frida-server-14.0.6-android-arm"

# Frida-server 在本地路径
FRIDA_SERVER_LOCAL_PATH = normcase(join(BASE_PATH, "libs/frida-server")).replace("\\", sep)

# 脱壳DEX保存路径
DEX_SAVE_PATH = ""

# 创建最多docker容器
CONTAINER_MAX = 3
