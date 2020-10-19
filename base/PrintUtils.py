

# class PrintUtils:
redPrint = "\033[31m"
greenPrint = "\033[32m"
yellowPrint = "\033[33m"
bluePrint = "\033[34m"
yellowLinePrint = "\033[1;4;33m"
geenLinePrint = "\033[1;4;32m"
geenBackPrint = "\033[1;4;42m"
endPrint = "\033[0m"

# red--echo -e "\033[31m${*}\033[0m"
# green -e "\033[32m${*}\033[0m"
##红色打印
def printRed(str):
    print(redPrint, str, endPrint)

def printGreenBash(str):
    print(greenPrint, str, endPrint, end=' ')

def printGreen(str):
    print(greenPrint, str, endPrint)

def printYellow(str):
    print(yellowPrint, str, endPrint)

def printYellowBash(str):
    print(yellowPrint, str, endPrint, end=' ')

def printBlue(str):
    print(bluePrint, str, endPrint)

def printYellowLine(str):
    print(yellowLinePrint, str, endPrint)

def printLine(str):
    print(geenLinePrint, str, endPrint)