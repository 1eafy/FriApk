from subprocess import Popen, PIPE, STDOUT


def command(cmd, encoding="UTF-8", read_rev=True):
    try:
        result = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
        if read_rev:
            result_text = result.stdout.read().decode(encoding)
            result.kill()
            return result_text
    except Exception as e:
        print(f"[Error] Command execution error, ", e)