from subprocess import Popen, PIPE, STDOUT


def command(cmd, encoding="UTF-8"):
    try:
        result = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
        result_text = result.stdout.read().decode(encoding)
        result.kill()
        return result_text
    except Exception as e:
        print(f"[Error] Command execution error")
        print(e)