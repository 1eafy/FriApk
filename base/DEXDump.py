# Author: hluwa <hluwa888@gmail.com>
# HomePage: https://github.com/hluwa
# CreatedTime: 2020/1/7 20:57

import os
import sys

import click
import frida
import logging

from config.config import BASE_PATH, ADB_PATH

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt='%m-%d/%H:%M:%S')


def get_all_process(device, pkgname):
    return [process for process in device.enumerate_processes() if process.name == pkgname]


def search(api, args=None):
    """
    """

    matches = api.scandex()
    for info in matches:
        click.secho("[DEXDump] Found: DexAddr={}, DexSize={}"
                    .format(info['addr'], hex(info['size'])), fg='green')
    return matches


def dump(pkg_name, api):
    """
    """
    matches = api.scandex()
    for num, info in enumerate(matches):
        try:
            bs = api.memorydump(info['addr'], info['size'])
            if not os.path.exists("./" + pkg_name + "/"):
                os.mkdir("./" + pkg_name + "/")
            if bs[:4] != "dex\n":
                bs = b"dex\n035\x00" + bs[8:]
            dex_name = "classes" + str(num)
            # dex_name = info['addr']
            with open(pkg_name + "/" + dex_name + ".dex", 'wb') as out:
            # with open(pkg_name + "/" + info['addr'] + ".dex", 'wb') as out:
                out.write(bs)
            click.secho("[DEXDump]: DexSize={}, DexAddr={}, SavePath={}/{}/{}.dex"
                        .format(hex(info['size']), info['addr'], os.path.normcase(os.getcwd()), pkg_name, dex_name), fg='green')
        except Exception as e:
            click.secho("[Except] - {}: {}".format(e, info), bg='yellow')


def dumpDex():
    try:
        device = frida.get_usb_device()
    except:
        device = frida.get_remote_device()
    print(device)
    target = device.get_frontmost_application()
    pkg_name = target.identifier
    print(pkg_name+"++++++++++++++")
    processes = get_all_process(device, pkg_name)
    if len(processes) == 1:
        target = processes[0]
    else:
        from time import sleep
        sleep(5)
        target = device.get_frontmost_application()
        pkg_name = target.identifier
        print(pkg_name)
        s_processes = ""
        for index in range(len(processes)):
            s_processes += "\t[{}] {}\n".format(index, str(processes[index]))
        input_id = int(input("[{}] has multiprocess: \n{}\nplease choose target process: "
                             .format(pkg_name, s_processes)))
        target = processes[input_id]
        try:
            for index in range(len(processes)):
                if index == input_id:
                    os.system("{} shell \"su -c 'kill -18 {}'\"".format(ADB_PATH, processes[index].pid))
                else:
                    os.system("{} shell \"su -c 'kill -19 {}'\"".format(ADB_PATH, processes[index].pid))
        except:
            pass

    logging.info("[DEXDump]: found target [{}] {}".format(target.pid, pkg_name))
    session = device.attach(target.pid)
    # path = os.path.dirname(sys.argv[0])
    # path = path if path else "."
    script = session.create_script(open(os.path.join(BASE_PATH, "base/agent.js")).read())
    script.load()

    dump(pkg_name, script.exports)
    return True
