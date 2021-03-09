import frida
import time
import os
from pprint import pprint as pp
from config.config import FRIDA_SCRIPT_PATH



def run(package_name):

    # package_name = "com.example.chap1"

    def my_message_handler(message, payload):
        pp(message)
        print('-' * 10)
        print(payload)

    device = frida.get_usb_device()
    print(device)
    pid = device.spawn([package_name])
    print(pid)
    device.resume(pid)
    time.sleep(1)
    session = device.attach(pid)
    print('----', session)
    for root, _, files in os.walk(FRIDA_SCRIPT_PATH):
        for file in files:
            with open(os.path.join(root, file), "r", encoding='utf8') as f:
                script = session.create_script(f.read())
            script.on("message", my_message_handler)
            script.load()

    # script.exports.callsecretfunction()

