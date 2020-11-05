from common.Utils import *
from re import findall
import uuid


class AVD:
    def __init__(self):
        self.container_id = ""
        self.container_name = ""
        self.port_list = []

    def new_avd(self):
        """
        -d: New container run in the background.
        -P: Random port mapping.
        :return:
        """
        self.container_name = self._get_uuid()
        print(f"docker run -d -P --name {self.container_name} android-emulator")
        self.container_id = command(f"docker run -d -P --name {self._get_uuid()} netdodo/android-emulator")
        print(self.container_id)


    def _get_uuid(self):
        """

        :return: uuid4
        """
        return "".join(str(uuid.uuid4()).split('-'))

    def get_mapping_port(self, container_id):
        port_mapping = command(f"docker port {self.container_id}")
        print(port_mapping)
        port_list = findall("5555/tcp -> 0\.0\.0\.0:(\d*)", port_mapping)
        print(port_list)
        print(type(port_list))
        return port_list

    def stop_container(self, container_id_or_name):
        print("stop container...")
        res = command(f"docker stop {container_id_or_name}")
        print(res)
        print("stop over...")


    def rm_container(self, container_id_or_name):
        print("rm container...")
        res = command(f"docker rm {container_id_or_name}")
        print(res)
        print("rm over...")


    def __del__(self):
        print("stop container and rm container ?????")
        self.stop_container(self.container_id)
        self.rm_container(self.container_id)


# if __name__ == '__main__':
#     a = """5555/tcp -> 0.0.0.0:32771
# 5037/tcp -> 0.0.0.0:32773
# 5554/tcp -> 0.0.0.0:32772"""
#     port_list = findall("0\.0\.0\.0:(\d*)", a)
#     print(port_list)
#     print(type(port_list))
