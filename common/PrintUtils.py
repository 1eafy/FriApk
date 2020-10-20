

# class PrintUtils:
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
YELLOWLINE = "\033[1;4;33m"
GREENLINE = "\033[1;4;32m"
geenBackPrint = "\033[1;4;42m"
END = "\033[0m"

# red--echo -e "\033[31m${*}\033[0m"
# green -e "\033[32m${*}\033[0m"
##红色打印
def printRed(str):
    print(RED, str, END)

def printGreenBash(str):
    print(GREEN, str, END, end=' ')

def printGreen(str):
    print(GREEN, str, END)

def printYellow(str):
    print(YELLOW, str, END)

def printYellowBash(str):
    print(YELLOW, str, END, end=' ')

def printBlue(str):
    print(BLUE, str, END)

def printYellowLine(str):
    print(YELLOWLINE, str, END)

def printLine(str):
    print(GREENLINE, str, END)