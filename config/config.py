from os.path import *
from os import *

TOOLS_PATH = join(getcwd(), 'libs')

# 项目根目录
BASE_PATH = dirname(dirname(abspath(__file__)))

# 反编译工具Jadx绝对路径
JADX_PATH = r"E:\file\Android\jadx-1.1.0\bin\jadx.bat"

# ADB绝对路径
ADB_PATH = normcase(join(BASE_PATH, "libs/adb.exe")).replace("\\", sep)

# Frida-server在模拟器中的绝对路径
FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"

# 脱壳DEX保存路径
DEX_SAVE_PATH = ""