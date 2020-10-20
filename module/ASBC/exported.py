class Module:
    def __init__(self, apk):
        self.apk = apk
        self.module_info = {
            "Name": "",
            "Author": "",
            "Date": "",
            "Description": "",
            "Reference": [
                "",
            ],
        }

        self.status = False

    def run(self):
        return {
            "status": self.status,
            'result': None
        }