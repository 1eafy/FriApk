"""
@Date: 2020-10-7 11:54
"""

import argparse
from base.FriApk_v2 import FriApk
# from base.FriApk import FriApk

__toolsName__ = "FriApk"
__version__ = "0.1"
__author__ = "***"

def banner():
    print("""
    ___________      .__   _____          __    
    \_   _____/______|__| /  _  \ ______ |  | __
     |    __) \_  __ \  |/  /_\  \\____ \|  |/ /
     |     \   |  | \/  /    |    \  |_> >    < 
     \___  /   |__|  |__\____|__  /   __/|__|_ \\
         \/                     \/|__|        \/
    """)

def main():
    banner()
    description = f"{__toolsName__} - {__version__}"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("apk")
    parser.add_argument("--module", help="run the provided module only")
    parser.add_argument("--static-only", help="rely only on static analysis", action="store_true", default=True)
    args = parser.parse_args()
    apk = FriApk(args)
    # apk = FriApk(r"C:\Users\acer\Desktop\testApk\轻启动_2.15.0.apk")
    apk.load_apk()


if __name__ == '__main__':
    main()