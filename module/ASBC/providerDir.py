class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "",
            "Author": "xxx",
            "Date": "2020.10.21",
            "Description": "",
            "Reference": [
                "",
            ],
        }

        self.status = False

    def run(self):
        # for dex in self.apk.get_all_dex():
        #     # print(dex)
        #     dv = dvm.DalvikVMFormat(dex)
        #     for s in dv.get_strings():
        #         # printGreen(s.decode('utf8'))
        #         s = s.decode("utf8")
        #         if "content://" in s:
        #             print(s)


        self.status = False

        return {
            "status": self.status,
            'result': None
        }