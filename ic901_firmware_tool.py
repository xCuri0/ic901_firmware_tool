"""
MIT License

Copyright (c) xCuri0 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 """
import re
import os
import io
import sys
import argparse
import itertools
import configparser
import capstone
import keystone
from capstone.mips import *
from packaging.version import Version
from colorama import Fore, Style, just_fix_windows_console

EBASE = 0x9d006000
# ivt spacing
IntCtlVS = 0x20
TMR2_VECTOR = 8

CODE_SIZE = 0x19000

# bInterval for EP82/EP83
EP82 = rb"\x09\x21\x00\x01\x00\x01\x22.\x00\x07\x05\x82\x03\x40\x00(.)"
EP83 = rb"\x09\x21\x00\x01\x00\x01\x22.\x00\x07\x05\x83\x03\x0c\x00(.)"

cs = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN)
ks = keystone.Ks(keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32 + keystone.KS_MODE_LITTLE_ENDIAN)

def printAddress(name, address, silent, gp=False):
    if silent:
        return

    GP_REG = 0x7ff0

    if not gp:
        print(f"{name} @ 0x{address:x}")
    else:
        print(f"{name} @ MEM 0x{GP_REG + address:x}")

def findTmr2ISR(code, silent):
    TMR2_IVT = EBASE + 0x200 + (TMR2_VECTOR * IntCtlVS)

    printAddress("Timer2IVT", TMR2_IVT, silent)

    for ins in itertools.dropwhile(lambda i: i.address < TMR2_IVT, code):
        if ins.id == MIPS_INS_J:
            return ins.operands[0].imm

        if ins.address > TMR2_IVT + IntCtlVS:
            break

    return None

def findCoilOnTicks(code, tmr2ISR, silent):
    tempCoilOnTicks = None
    setCoilOnTicks = None
    _coilOnTicksIns = None

    # locate variable storing how many TMR2 ticks EMR coil charges pen for
    prev = None
    for ins in itertools.dropwhile(lambda i: i.address < tmr2ISR, code):
        # find addiu $A, $A, -1
        if prev and ins.id == MIPS_INS_ADDIU and ins.operands[0].reg == ins.operands[1].reg and ins.operands[2].imm == -1:
            if prev.id == MIPS_INS_LW and ins.operands[0].reg == prev.operands[0].reg and prev.operands[1].reg == MIPS_REG_GP:
                tempCoilOnTicks = prev.operands[1].mem.disp
                break

        # end of function
        if ins.id == MIPS_INS_ERET:
            break

        prev = ins

    if tempCoilOnTicks:
        printAddress("tempCoilOnTicks", tempCoilOnTicks, silent, gp=True)
    else:
        print("Couldn't find tempCoilOnTicks")
        return None

    # find:
    # lbu $?,-0x????($gp)
    # sw $?, -0x7c44($gp)
    prev = None
    for ins in code:
        if prev and prev.id == MIPS_INS_LBU and ins.id == MIPS_INS_SW:
            if prev.operands[0].reg == ins.operands[0].reg and ins.operands[1].mem.disp == tempCoilOnTicks:
                setCoilOnTicks = prev.operands[1].mem.disp
                break

        prev = ins

    if setCoilOnTicks:
        printAddress("setCoilOnTicks", setCoilOnTicks, silent, gp=True)
    else:
        print("Couldn't find setCoilOnTicks")
        return None

    # find sb $v1, setCoilOnTicks(gp)
    prev = None
    for ins in code:
        if prev and prev.id == MIPS_INS_ADDIU and ins.id == MIPS_INS_SB:
            if prev.operands[0].reg == ins.operands[0].reg and ins.operands[1].mem.disp == setCoilOnTicks:
                _coilOnTicksIns = prev
                break
        prev = ins

    return _coilOnTicksIns

def findADCSampler(code, tmr2ISR):
    # find jal to ADC sample process function
    for ins in itertools.dropwhile(lambda i: i.address < tmr2ISR, code):
        if ins.id == MIPS_INS_JAL:
            return ins.operands[0].imm

        # end of function
        if ins.id == MIPS_INS_ERET:
            break

    return None

def findADCSampleCount(code, samplerAddr):
    instructions = []

    # look for
    # li        $?,0x32
    # lw        $A, ????(gp)
    # ????      $A (so patched firmware still can be read)
    # andi      $A,$A,0xff
    for ins in itertools.dropwhile(lambda i: i.address < samplerAddr, code):
        if len(instructions) >= 4:
            # for some reason "li $v1,0x32" in Ghidra becomes "addiu $v1, $zero, 0x32"
            if ins.id == MIPS_INS_ANDI and ins.operands[2].imm == 0xff and instructions[-2].id == MIPS_INS_LW and instructions[-3].id == MIPS_INS_ADDIU:
                yield (instructions[-1], instructions[-3])
                instructions = []

        if ins.id == MIPS_INS_JR:
            break

        instructions.append(ins)

def findADCMidSample(code, samplerAddr):
    instructions = []

    # look for
    # li        $A, adcMidSample
    # ...
    # beql      $?,$A,????
    # _andi     $?,$?,0xffff
    for ins in itertools.dropwhile(lambda i: i.address < samplerAddr, code):
        if len(instructions) >= 4:
            if ins.id == MIPS_INS_ANDI and ins.operands[2].imm == 0xffff and instructions[-1].id == MIPS_INS_BEQL:
                reg = instructions[-1].operands[1].reg
                for ins2 in reversed(instructions):
                    # li becomes addiu here too
                    if ins2.id == MIPS_INS_ADDIU and ins2.operands[0].reg == reg:
                        return ins2

                break

        if ins.id == MIPS_INS_JR:
            break

        instructions.append(ins)

    return None

def findADCSamplerScanArea(code, samplerAddr, silent):
    instructions = []

    # look for
    # lbu       $A,????($gp)=>scanPhase
    # addiu     $B, $zero, 0x2 ; 0x2 is X coil scanPhase
    # bne       $A,$B, selectYCoil ; jump to Y coil if else if not 0x2
    # addiu     $B, $zero, 0x5 ; delay set 0x5 still applies when jump to Y coil if else
    # lbu       $A,0x????($gp)=>scanIndex
    # (selectXCoil if else below)
    # ...
    # selectYCoil:
    # bne       $A,$B, LAB_???? ; skip setting readYcoil
    # lbu       $A,0x????(gp)=>scanIndex
    # (Y coil if else below)

    selectXCoilAddr = None
    selectYCoilAddr = None
    scanIndexMem = None

    for ins in itertools.dropwhile(lambda i: i.address < samplerAddr, code):
        if len(instructions) >= 5:
            if (instructions[-5].id == MIPS_INS_LBU and
                instructions[-4].id == MIPS_INS_ADDIU and instructions[-4].operands[2].imm == 0x2 and
                instructions[-3].id == MIPS_INS_BNE and
                instructions[-2].id == MIPS_INS_ADDIU and instructions[-2].operands[2].imm == 0x5 and
                instructions[-1].id == MIPS_INS_LBU
                ):
                scanIndexMem = instructions[-1].operands[1].mem.disp

                # current address is start of X coil selector
                selectXCoilAddr = ins.address
                tempYCoilAddr = instructions[-3].operands[2].imm

                # actual selectYCoil address which is after scanIndex is set
                prev = None
                for ins2 in itertools.dropwhile(lambda i: i.address < tempYCoilAddr, code):
                    if prev and prev.id == MIPS_INS_LBU and prev.operands[1].mem.disp == scanIndexMem:
                        selectYCoilAddr = ins2.address
                        break

                    prev = ins2
                    if ins2.id == MIPS_INS_JR:
                        break
                break

        if ins.id == MIPS_INS_JR:
            break

        instructions.append(ins)

    if selectYCoilAddr is not None:
        printAddress("selectXCoil", selectXCoilAddr, silent)
        printAddress("selectYCoil", selectYCoilAddr, silent)
        printAddress("scanIndex", scanIndexMem, silent, gp=True)
    else:
        print("Couldn't find ADCSamplerScanArea")

    # find instructions used for coil selected
    def findCoilSelectIns(selectCoilAddr):
        i = 0
        jmpAddr = selectCoilAddr
        instructions = []
        while (i <= 7):
            b = False
            for ins in itertools.dropwhile(lambda i: i.address < jmpAddr, code):
                bneIns = None
                delaySlotIns = None
                #selectCoilIns = None
                if ins.id == MIPS_INS_BNE:
                    jmpAddr = ins.operands[2].imm
                    bneIns = ins
                elif ins.id == MIPS_INS_BNEZ:
                    jmpAddr = ins.operands[1].imm
                    bneIns = ins
                elif ins.id == MIPS_INS_J:
                    jmpAddr = ins.operands[0].imm
                    bneIns = ins
                else:
                    b = True
                    break

                # on 6th instruction there's no delay slot and coilSelect gets jumped in 5x5
                if i <= 5:
                    # get the delay slot instruction
                    iterIns = itertools.dropwhile(lambda i: i.address < ins.address, code)
                    next(iterIns)
                    delaySlotIns = next(iterIns)

                    # again we don't need to modify selectCoil on 1st or center 4th
                    #if not (i == 0 or i == 3):
                    #    for ins2 in iterIns:
                    #        if ins2.id == MIPS_INS_ADDIU and ins2.operands[0].reg == ins2.operands[1].reg:
                    #            selectCoilIns = ins2
                    #            break

                instructions.append((bneIns, delaySlotIns))
                break
            if b:
                break
            i += 1

        # there should be 7 jumps
        if not i == 7:
            return None

        return instructions

    # skip checking for scanXIndex / scanYIndex assign on first and last
    _selectInstructionsX = findCoilSelectIns(selectXCoilAddr)
    _selectInstructionsY = findCoilSelectIns(selectYCoilAddr)

    if scanIndexMem is None or _selectInstructionsX is None or _selectInstructionsY is None:
        return None

    return (scanIndexMem, _selectInstructionsX, _selectInstructionsY)

def findScanIndexAreaIns(code, scanIndexMem):
    scanIndexAreaX = None
    scanIndexAreaY = None

    # find
    # lbu       $A,scanIndexMem($gp)
    # sltiu     $A,$A,0x7
    prev = None
    for ins in code:
        if prev and (
            prev.id == MIPS_INS_LBU and prev.operands[1].mem.disp == scanIndexMem and
            ins.id == MIPS_INS_SLTIU and prev.operands[0].reg == ins.operands[0].reg == ins.operands[1].reg and (ins.operands[2].imm == 5 or ins.operands[2].imm == 7)
        ):
            scanIndexAreaX = ins
            break

        prev = ins

    # find
    # sb        $A,scanIndexMem($gp)
    # sw        ???
    # sw        ???
    # lbu       ???
    # sltiu     $A,$A,0x7
    instructions = []
    for ins in code:
        if len(instructions) >= 4 and (
            instructions[-4].id == MIPS_INS_SB and instructions[-4].operands[1].mem.disp == scanIndexMem and
            instructions[-3].id == MIPS_INS_SW and instructions[-2].id == MIPS_INS_SW and instructions[-1].id == MIPS_INS_LBU and
            ins.id == MIPS_INS_SLTIU and instructions[-4].operands[0].reg == ins.operands[0].reg == ins.operands[1].reg and
            (ins.operands[2].imm == 5 or ins.operands[2].imm == 7)
        ):
            scanIndexAreaY = ins
            break

        instructions.append(ins)

    return scanIndexAreaX, scanIndexAreaY

def findDeadzoneSmoothIns(code):
    # find
    # subu      a1,v0,a2
    # sra       a0,a1,0x1f
    # xor       a1,a0,a1
    # subu      t0,a1,a0
    # subu      a1,v1,a3
    # sra       a0,a1,0x1f
    # xor       a1,a0,a1
    # subu      a0,a1,a0
    # addu      a0,t0,a0
    # lbu       t0,????(gp)=>smoothingDeadzone
    # slt       a0,a0,t0

    deadzoneAndIns = []
    deadzoneMemIns = []
    instructions = []

    codeIter = iter(code)
    for ins in codeIter:
        if len(instructions) >= 9 and (
            instructions[-9].id == MIPS_INS_SUBU and
            instructions[-8].id == MIPS_INS_SRA and instructions[-8].operands[2].imm == 0x1f and
            instructions[-7].id == MIPS_INS_XOR and
            instructions[-6].id == MIPS_INS_SUBU and
            instructions[-5].id == MIPS_INS_SUBU and
            instructions[-4].id == MIPS_INS_SRA and instructions[-4].operands[2].imm == 0x1f and
            instructions[-3].id == MIPS_INS_XOR and
            instructions[-2].id == MIPS_INS_SUBU and
            instructions[-1].id == MIPS_INS_ADDU
        ):
            nextIns = next(codeIter)

            # deadzone gets set by 1st function parameter, move up until we find it
            if ins.id == MIPS_INS_SLT and ins.operands[2].reg == MIPS_REG_A0:
                for ins2 in reversed(instructions):
                    if ins2.id == MIPS_INS_ANDI and ins2.operands[0].reg == ins2.operands[1].reg == MIPS_REG_A0 and ins2.operands[2].imm == 0xff:
                        deadzoneAndIns.append(ins2)
                        break

                    # patched instruction
                    elif ins2.id == MIPS_INS_ADDIU and ins2.operands[0].reg == MIPS_REG_A0 and ins2.operands[1].reg == MIPS_REG_ZERO:
                        deadzoneAndIns.append(ins2)
                        break

            # deadzone gets set by memory offset
            elif ins.id == MIPS_INS_LBU and nextIns.id == MIPS_INS_SLT and nextIns.operands[2].reg == ins.operands[0].reg:
                skipAppend = False
                for ins2 in deadzoneMemIns:
                    if not ins.operands[1].mem.disp == ins2.operands[1].mem.disp:
                        print("Invalid instruction in deadzone")
                        return (None, None)

                if not skipAppend:
                    deadzoneMemIns.append(ins)

            # patched instruction
            elif ins.id == MIPS_INS_ADDIU and ins.operands[1].reg == MIPS_REG_ZERO and nextIns.operands[2].reg == ins.operands[0].reg:
                deadzoneMemIns.append(ins)

        instructions.append(ins)

    if len(deadzoneAndIns) > 1:
        print(f"Found too many deadzoneAndIns instructions {deadzoneAndIns}")
        return (None, None)
    elif len(deadzoneAndIns) == 1:
        deadzoneAndIns = deadzoneAndIns[0]
    else:
        print("Failed to find deadzoneAndIns")
        return (None, None)

    # find
    # addiu $A, $zero, 0xa
    # sb $A, smoothingDeadzone

    return (deadzoneAndIns, deadzoneMemIns)


coilOnTicksIns = None
adcMaxSampleCountInsArr = [] # only used on unpatched fw
adcSampleCountInsArr = []
adcMidSampleIns = None

EP82bIntervalOffset = None
EP82bIntervalVal = None

EP83bIntervalOffset = None
EP83bIntervalVal = None

selectInstructionsX = None
selectInstructionsY = None
scanIndexAreaXIns = None
scanIndexAreaYIns = None
scanArea5x5 = False

smoothDzAndIns = None
smoothDzSetInsArr = None

# load instructions/offsets from firmware
def firmware_read(filePath, silent=False):
    global coilOnTicksIns
    global adcSampleCountInsArr
    global adcMaxSampleCountInsArr
    global adcMidSampleIns

    global EP82bIntervalOffset
    global EP82bIntervalVal

    global EP83bIntervalOffset
    global EP83bIntervalVal

    global selectInstructionsX
    global selectInstructionsY

    global scanIndexAreaXIns
    global scanIndexAreaYIns

    global scanArea5x5

    global smoothDzAndIns
    global smoothDzSetInsArr

    # clear values before reading again
    coilOnTicksIns = None

    adcMaxSampleCountInsArr = []
    adcSampleCountInsArr = []
    adcMidSampleIns = None

    EP82bIntervalOffset = None
    EP82bIntervalVal = None
    EP83bIntervalOffset = None
    EP83bIntervalVal = None

    selectInstructionsX = None
    selectInstructionsY = None

    scanIndexAreaXIns = None
    scanIndexAreaYIns = None

    scanArea5x5 = False

    smoothDzAndIns = None
    smoothDzSetInsArr = None


    with open(filePath, 'rb') as f:
        fSize = f.seek(0, 2)
        if not fSize == CODE_SIZE:
            print(f"{Fore.LIGHTRED_EX}Input file must be {CODE_SIZE} bytes")
            return False

        if not silent:
            print(f"Calculating firmware offsets for {Fore.LIGHTYELLOW_EX}{filePath}{Fore.RESET}\n")

        cs.detail = True
        # remove this and use CS_MODE_MIPS32R2 when capstone updates, currently rdpgpr is unrecognized
        cs.skipdata = True

        f.seek(0)
        code_bytes = f.read()
        code = list(cs.disasm(code_bytes, EBASE))

        tmr2ISR = findTmr2ISR(code, silent)
        if tmr2ISR:
            printAddress("Timer2ISR", tmr2ISR, silent)
        else:
            print("Couldn't find Timer2 ISR")
            return False

        coilOnTicksIns = findCoilOnTicks(code, tmr2ISR, silent)
        if coilOnTicksIns:
            printAddress("coilOnTicks", coilOnTicksIns.address, silent)
        else:
            print("Couldn't find coilOnTicks")
            return False

        samplerAddr = findADCSampler(code, tmr2ISR)
        if samplerAddr:
            printAddress("ADCSampler()", samplerAddr, silent)
        else:
            print("Couldn't find ADC Sampler function")
            return False


        scanAreaRet = findADCSamplerScanArea(code, samplerAddr, silent)

        if scanAreaRet:
            scanIndexMem, selectInstructionsX, selectInstructionsY = scanAreaRet
            if selectInstructionsX[0][0].id == MIPS_INS_J or selectInstructionsY[0][0].id == MIPS_INS_J:
                scanArea5x5 = True
                if not silent:
                    print("5x5 scan area (patched)")
            else:
                scanArea5x5 = False
                if not silent:
                    print("7x7 scan area (stock)")
        else:
            print(f"{Fore.LIGHTRED_EX}Failed to find scan area instructions{Fore.RESET}")
            return False

        scanIndexAreaXIns, scanIndexAreaYIns = findScanIndexAreaIns(code, scanIndexMem)

        if not scanIndexAreaXIns:
            print("Couldn't find scanIndexAreaX")
            return False
        else:
            printAddress("scanIndexAreaX", scanIndexAreaXIns.address, silent)

        if not scanIndexAreaYIns:
            print("Couldn't find scanIndexAreaY")
            return False
        else:
            printAddress("scanIndexAreaY", scanIndexAreaYIns.address, silent)

        adcSampleCount2Arr = list(findADCSampleCount(code, samplerAddr))

        if len(adcSampleCount2Arr) != 2 or not adcSampleCount2Arr[0][0].id == adcSampleCount2Arr[1][0].id:
            print("Couldn't find ADC sample count instructions")
            return False
        else:
            for i, ins in enumerate(adcSampleCount2Arr):
                adcSampleCountInsArr.append(ins[0])
                adcMaxSampleCountInsArr.append(ins[1])
                printAddress(f"adcSampleCount #{i + 1}", ins[0].address, silent)

        adcMidSampleIns = findADCMidSample(code, samplerAddr)

        if adcMidSampleIns:
            printAddress("adcMidSample", adcMidSampleIns.address, silent)
        else:
            print("Couldn't find adcMidSample")
            return False

        smoothDzAndIns, smoothDzSetInsArr = findDeadzoneSmoothIns(code)

        if (smoothDzAndIns is None):
            print("Couldn't find smoothDzAndIns")
            return False

        if (smoothDzSetInsArr is None):
            print("Couldn't find smoothDzSetInsArr")
            return False

        printAddress("smoothDzAndIns", smoothDzAndIns.address, silent)

        for i, ins in enumerate(smoothDzSetInsArr):
            printAddress(f"smoothDzSetIns #{i}", ins.address, silent)

        try:
            ep82Match = re.search(EP82, code_bytes)
            ep83Match = re.search(EP83, code_bytes)

            if ep82Match is None or ep83Match is None:
                raise Warning

            EP82bIntervalOffset = EBASE + ep82Match.start(1)
            EP83bIntervalOffset = EBASE + ep83Match.start(1)

            if EP82bIntervalOffset is None or EP83bIntervalOffset is None:
                raise Warning

        except Warning:
            print("Failed to locate EP82/EP82 bInterval")
            return False

        printAddress("EP82 bInterval", EP82bIntervalOffset, silent)
        printAddress("EP83 bInterval", EP83bIntervalOffset, silent)

        f.seek(EP82bIntervalOffset - EBASE)
        EP82bIntervalVal = int.from_bytes(f.read(1), 'little')

        f.seek(EP83bIntervalOffset - EBASE)
        EP83bIntervalVal = int.from_bytes(f.read(1), 'little')

        return True

def firmware_info():
    print(f"coilOnTicks = {coilOnTicksIns.operands[2].imm}")

    if scanArea5x5:
        print("scanArea = 5x5")
    else:
        print("scanArea = 7x7")

    if adcSampleCountInsArr[0].id == MIPS_INS_ADDIU: # patched fw
        print(f"adcSampleCount #1 = {adcSampleCountInsArr[0].operands[2].imm}")
        print(f"adcSampleCount #2 = {adcSampleCountInsArr[1].operands[2].imm}")
    else: # default fw
        print(f"adcSampleCount #1 = {adcMaxSampleCountInsArr[0].operands[2].imm}-N (stock)")
        print(f"adcSampleCount #2 = {adcMaxSampleCountInsArr[1].operands[2].imm}-N (stock)")

    print(f"adcMidSample = {adcMidSampleIns.operands[2].imm}")

    if smoothDzAndIns.id == MIPS_INS_ANDI:
        print("deadzone = AUTO")
    elif smoothDzAndIns.id == MIPS_INS_ADDIU: # patched fw
        print(f"deadzone = {smoothDzAndIns.operands[2].imm}")

    print(f"EP82bInterval = {EP82bIntervalVal}")
    print(f"EP83bInterval = {EP83bIntervalVal}")

# load config from currently loaded firmware file
def load_config_fw():
    cfg = {}
    cfg['coilOnTicks'] = str(coilOnTicksIns.operands[2].imm)

    if scanArea5x5:
        cfg['scanArea'] = "5x5" # patched
    else:
        cfg['scanArea'] = "7x7" # stock

    cfg['adcMaxSampleCount'] = adcMaxSampleCountInsArr[0].operands[2].imm

    if adcSampleCountInsArr[0].id == MIPS_INS_ADDIU: # patched fw
        cfg['adcSampleCount'] = str(adcSampleCountInsArr[0].operands[2].imm)
    else: # default fw
        cfg['adcSampleCount'] = 'AUTO'

    cfg['adcMidSample'] = str(adcMidSampleIns.operands[2].imm)

    if smoothDzAndIns.id == MIPS_INS_ANDI:
        cfg['deadzone'] = "AUTO"
    elif smoothDzAndIns.id == MIPS_INS_ADDIU: # patched fw
        cfg['deadzone'] = str(smoothDzAndIns.operands[2].imm)
    else:
        print("Corrupt firmware smoothing functon")
        return None

    cfg['bInterval'] = str(EP82bIntervalVal)

    return cfg

# load config from ini
def load_config_ini(cfgFile):
    cfg = {}

    config = configparser.ConfigParser()
    config.read(cfgFile)

    cfg['coilOnTicks'] = config['CoilScan']['coilOnTicks']
    cfg['scanArea'] = config['CoilScan']['scanArea']

    cfg['adcSampleCount'] = config['CoilScan']['adcSampleCount']
    cfg['adcMidSample'] = config['CoilScan']['adcMidSample']

    cfg['deadzone'] = config['Smoothing']['deadzone']

    cfg['bInterval'] = config['USB']['bInterval']

    return cfg

# save loaded config to ini
def save_config_ini(filePath, cfg):
    config = configparser.ConfigParser(allow_no_value=True)
    config.optionxform = str

    adcMaxSampleCount = adcMaxSampleCountInsArr[0].operands[2].imm

    config.add_section('CoilScan')
    config.set('CoilScan', '; Number of TMR2 ticks pen is charged for before reading during each coil scan, 3 - 50. Setting a value too low increases jitter especially while hovering.', None)
    config.set('CoilScan', '; Recommened to reduce by increments of 5 after adjusting others, it only gives a small report rate increase in exchange for higher jitter.', None)
    config.set('CoilScan', 'coilOnTicks', cfg['coilOnTicks'])

    config.set('CoilScan', '; Scan area surrounding pen, 7x7 (default) or 5x5 (faster). 5x5 may affect tilt detection/correction but in most cases it feels identical.', None)
    config.set('CoilScan', 'scanArea', cfg['scanArea'])

    config.set('CoilScan', f'; ADC sample count for each coil scan, 5 - {adcMaxSampleCount} or AUTO to use default. Use as few as possible to maximize report rate.', None)
    config.set('CoilScan', 'adcSampleCount', cfg['adcSampleCount'])

    config.set('CoilScan', '; ADC middle sample, 4 to adcSampleCount-1. Recommend to either keep default or set lowest possible.')
    config.set('CoilScan', 'adcMidSample', cfg['adcMidSample'])

    config.add_section('Smoothing')
    config.set('Smoothing', '; Smoothing deadzone around pen 0 - 10 or AUTO. Recommend setting to 0.', None)
    config.set('Smoothing', 'deadzone', cfg['deadzone'])

    config.add_section('USB')
    config.set('USB', '; USB bInterval in milliseconds 1 - 4. Setting to 1 is recommended.', None)
    config.set('USB', 'bInterval', cfg['bInterval'])

    print(f"\nSaving config to {Fore.LIGHTYELLOW_EX}{filePath}{Fore.RESET}")
    with open(filePath, 'w') as configfile:
        config.write(configfile)

def writeInstruction(buf, oldIns, instruction):
    encoding, _ = ks.asm(instruction, oldIns.address, as_bytes=True)
    if not len(encoding) == 4:
        print('Keystone produced instruction not 4 bytes, aborting')
        return False

    # write patched instruction
    buf.seek(oldIns.address - EBASE)
    buf.write(encoding)

    # for the .set noreorder workaround
    instruction = instruction.splitlines()[-1]
    print(f"{Fore.LIGHTMAGENTA_EX}{oldIns.address:x}{Fore.RESET}: {Fore.CYAN}{oldIns.mnemonic} {oldIns.op_str}{Fore.RESET} -> {Fore.LIGHTCYAN_EX}{instruction}{Fore.RESET}")
    return True

# patch firmware using config
def firmware_patch(inPath, outPath, cfg, cfgName):
    autoSampleCount = False
    autoDeadzone = False
    adcMaxSampleCount = adcMaxSampleCountInsArr[0].operands[2].imm

    fileName = os.path.basename(inPath)

    print(f"\nChecking {Fore.LIGHTYELLOW_EX}{cfgName}{Fore.RESET}\n")
    # check if cfg valid
    cfg['coilOnTicks'] = int(cfg['coilOnTicks'])
    if not 3 <= cfg['coilOnTicks'] <= 50:
        print("coilOnTicks must be 3 to 50")
        return False

    if not (cfg['scanArea'] == '7x7' or cfg['scanArea'] == '5x5'):
        print("scanArea must be 7x7 or 5x5")
        return False

    if not cfg['adcSampleCount'] == 'AUTO':
        cfg['adcSampleCount'] = int(cfg['adcSampleCount'])
        if not 5 <= cfg['adcSampleCount'] <= adcMaxSampleCount:
            print(f"adcSampleCount must be 5 to adcMaxSampleCount({adcMaxSampleCount}) or AUTO")
            return False

        adcMaxSampleCount = cfg['adcSampleCount']
    else:
        autoSampleCount = True

    cfg['adcMidSample'] = int(cfg['adcMidSample'])
    if not 4 <= cfg['adcMidSample'] <= adcMaxSampleCount-1:
        print(f"adcMidSample must be 4 to adcSampleCount-1 ({adcMaxSampleCount})")
        return False

    if not cfg['deadzone'] == 'AUTO':
        cfg['deadzone'] = int(cfg['deadzone'])
        if not 0 <= cfg['deadzone'] <= 10:
            print("deadzone must be 0 to 10 or AUTO")
            return False
    else:
        autoDeadzone = True

    cfg['bInterval'] = int(cfg['bInterval'])
    if not 1 <= cfg['bInterval'] <= 4:
        print("bInterval must be 1 to 4")
        return False

    print(f"Patching firmware {Fore.LIGHTYELLOW_EX}{fileName}{Fore.RESET}\n")

    origBuffer = None
    with open(inPath, 'rb') as f:
        origBuffer = f.read()

    with io.BytesIO(origBuffer) as buf:
        # patch using keystone

        def patchCoilOnTicks():
            print("Patching coilOnTicks:")
            dst = cs.reg_name(coilOnTicksIns.operands[0].reg)

            instruction = f"addiu ${dst}, $zero, 0x{cfg['coilOnTicks']:x}"

            if not writeInstruction(buf, coilOnTicksIns, instruction):
                return False

            return True

        def patchADCSampleCount():
            print("Patching adcSampleCount:")
            for adcSampleCountIns in adcSampleCountInsArr:
                # we can't restore auto sample count on patched firmware
                if autoSampleCount and not adcSampleCountIns.id == MIPS_INS_SUBU:
                    print("Cannot restore AUTO adcSampleCount, make sure input is unmodified")
                    return False
                elif autoSampleCount:
                    print("Skip patching adcSampleCount it's AUTO")
                    return True

                dst = cs.reg_name(adcSampleCountIns.operands[0].reg)

                instruction = f"addiu ${dst}, $zero, 0x{cfg['adcSampleCount']:x}"

                if not writeInstruction(buf, adcSampleCountIns, instruction):
                    return False

            return True

        def patchADCMidSample():
            print("Patching adcMidSample:")
            dst = cs.reg_name(adcMidSampleIns.operands[0].reg)

            instruction = f"addiu ${dst}, $zero, 0x{cfg['adcMidSample']:x}"

            if not writeInstruction(buf, adcMidSampleIns, instruction):
                return False

            return True

        def patchbInterval():
            print("Patching bInterval:")

            buf.seek(EP82bIntervalOffset - EBASE)
            buf.write(cfg['bInterval'].to_bytes(1, 'little'))

            print(f"{Fore.LIGHTMAGENTA_EX}{EP82bIntervalOffset:x}{Fore.RESET}: EP82 bInterval {Fore.CYAN}{EP82bIntervalVal}ms{Fore.RESET} -> {Fore.LIGHTCYAN_EX}{cfg['bInterval']}ms{Fore.RESET}")

            buf.seek(EP83bIntervalOffset - EBASE)
            buf.write(cfg['bInterval'].to_bytes(1, 'little'))

            print(f"{Fore.LIGHTMAGENTA_EX}{EP83bIntervalOffset:x}{Fore.RESET}: EP83 bInterval {Fore.CYAN}{EP83bIntervalVal}ms{Fore.RESET} -> {Fore.LIGHTCYAN_EX}{cfg['bInterval']}ms{Fore.RESET}")

            return True

        def patchScanArea():
            if scanArea5x5:
                print(f"{Fore.LIGHTRED_EX}Scan area is already patched, input firmware must be stock{Fore.RESET}")
                return False

            if cfg['scanArea'] == '7x7':
                print("Keeping default 7x7 scanArea")
                return True
            else:
                print(f"Patching scanArea {Fore.CYAN}7x7{Fore.RESET} -> {Fore.LIGHTCYAN_EX}5x5{Fore.RESET}")

            def patchCoilSelect(coilSelectInstructions):
                for i, ins in enumerate(coilSelectInstructions):
                    bneIns = ins[0]
                    delaySlotIns = ins[1]

                    # jump start and end because we only need 5 if else
                    if i in (0, 6):
                        jumpAddr = None

                        if i == 0 and bneIns.id == MIPS_INS_BNEZ:
                            jumpAddr = bneIns.operands[1].imm
                        elif i == 6 and bneIns.id == MIPS_INS_BNE:
                            jumpAddr = bneIns.operands[2].imm
                        else:
                            print(f"{Fore.LIGHTRED_EX}Unknown instruction, failed to patch coilSelect{Fore.RESET}")
                            return False

                        instruction = f"j 0x{jumpAddr:x}"

                        # without .set noreorder j becomes 8 bytes
                        if not writeInstruction(buf, bneIns, ".set noreorder\n" + instruction):
                            return False

                    # patch delay slot
                    if i < 5:
                        regName = None

                        if delaySlotIns.id == MIPS_INS_ADDIU and delaySlotIns.operands[1].reg == MIPS_REG_ZERO and delaySlotIns.operands[2].imm == i + 1:
                            regName = cs.reg_name(delaySlotIns.operands[0].reg)
                        else:
                            print(f"{Fore.LIGHTRED_EX}Unknown instruction, failed to patch coilSelect{Fore.RESET}")
                            return False

                        instruction = f"addiu ${regName}, $zero, {i}"

                        if not writeInstruction(buf, delaySlotIns, instruction):
                            return False

                return True
            def patchScanIndex(scanIndexIns):
                if scanIndexIns.id == MIPS_INS_SLTIU and scanIndexIns.operands[0].reg == scanIndexIns.operands[1].reg and scanIndexIns.operands[2].imm == 7:
                    reg_name = cs.reg_name(scanIndexIns.operands[1].reg)

                    instruction = f"sltiu ${reg_name}, ${reg_name}, 5"

                    # write patched instruction
                    if not writeInstruction(buf, scanIndexIns, instruction):
                        return False

                    return True
                else:
                    print(f"{Fore.LIGHTRED_EX}Unknown instruction, failed to patch scanIndex{Fore.RESET}")
                    return False

            print("\ncoilSelectX:")
            if not patchCoilSelect(selectInstructionsX):
                print(f"{Fore.LIGHTRED_EX}Failed to patch coilSelectX{Fore.RESET}")
                return False

            print("\ncoilSelectY:")
            if not patchCoilSelect(selectInstructionsY):
                print(f"{Fore.LIGHTRED_EX}Failed to patch coilSelectY{Fore.RESET}")
                return False

            print("\nscanIndexX:")
            if not patchScanIndex(scanIndexAreaXIns):
                print(f"{Fore.LIGHTRED_EX}Failed to patch scanIndexX{Fore.RESET}")
                return False

            print("\nscanIndexY:")
            if not patchScanIndex(scanIndexAreaYIns):
                print(f"{Fore.LIGHTRED_EX}Failed to patch scanIndexY{Fore.RESET}")
                return False

            return True

        def patchSmoothDz(smoothDzAnd, smoothDzSet):
            print("Patching smoothDeadzone:")

            if not autoDeadzone:
                if smoothDzAnd.id == MIPS_INS_ANDI and smoothDzAnd.operands[0].reg == smoothDzAnd.operands[1].reg == MIPS_REG_A0:
                    reg_name = cs.reg_name(smoothDzAnd.operands[0].reg)

                    instruction = f"addiu ${reg_name}, $zero, 0x{cfg['deadzone']:x}"

                    if not writeInstruction(buf, smoothDzAnd, instruction):
                        return False

                else:
                    print(f"{Fore.LIGHTRED_EX}Invalid smoothDzAnd instruction{Fore.RESET}")
                    return False
            else:
                if not smoothDzAnd.id == MIPS_INS_ANDI:
                    print(f"{Fore.LIGHTRED_EX}Cannot restore AUTO smoothDeadzone, input firmware must be stock{Fore.RESET}")
                    return False
                else:
                    print("Keeping AUTO smoothDeadzone")
                    return True

            for ins in smoothDzSet:
                if ins.id == MIPS_INS_LBU:
                    reg_name = cs.reg_name(ins.operands[0].reg)

                    instruction = f"addiu ${reg_name}, $zero, 0x{cfg['deadzone']:x}"

                    if not writeInstruction(buf, ins, instruction):
                        return False

                else:
                    print(f"{Fore.LIGHTRED_EX}Unknown instruction{Fore.RESET}")
                    return False

            return True


        if not patchCoilOnTicks():
            return False

        print("")

        if not patchScanArea():
            return False

        print("")

        if not patchADCSampleCount():
            return False

        print("")

        if not patchADCMidSample():
            return False

        print("")

        if not patchSmoothDz(smoothDzAndIns, smoothDzSetInsArr):
            return False

        print("")

        if not patchbInterval():
            return False

        print("")

        with open(outPath, "wb") as f:
            f.write(buf.getbuffer())

    print(f"Wrote patched firmware to {Fore.LIGHTYELLOW_EX}{outPath}{Fore.RESET}")
    return True

class CustomParser(argparse.ArgumentParser):
    def _custom_usage(self):
        return f"""
{Style.BRIGHT}{Fore.LIGHTBLUE_EX}save firmware config: {Fore.LIGHTMAGENTA_EX}{self.prog}{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}ic901-code.bin {Fore.CYAN}--save-cfg {Fore.LIGHTYELLOW_EX}ic901-code.ini
{Style.BRIGHT}{Fore.LIGHTBLUE_EX}patch firmware using config: {Fore.LIGHTMAGENTA_EX}{self.prog}{Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}ic901-code.bin {Fore.CYAN}--patch-cfg {Fore.LIGHTYELLOW_EX}ic901-code.ini {Fore.CYAN}--output {Fore.LIGHTYELLOW_EX}ic901-code-patched.bin

"""

    def format_usage(self):
        usage = super().format_usage()
        return usage + self._custom_usage()

    def format_help(self):
        usage = super().format_help()
        return usage + self._custom_usage()

class CustomFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(
            prog,
            indent_increment=2,
            max_help_position=30,
            width=None,
        )

def main():
    min_capstone = Version("5.0.7")
    if Version(capstone.__version__) < min_capstone:
        print(f"{Fore.LIGHTRED_EX}Current Capstone Engine version {Fore.LIGHTYELLOW_EX}{capstone.__version__}{Fore.LIGHTRED_EX} is too old, minimum supported is {Fore.CYAN}{min_capstone}{Fore.RESET}")
        print(f"{Style.BRIGHT}Older Capstone Engine versions don't handle MIPS addresses correctly and will result in a bricked tablet when patching")
        return 1

    min_keystone = Version("0.9.2")
    if Version(keystone.__version__) < min_keystone:
        print(f"{Fore.LIGHTRED_EX}Current Keystone Engine version {Fore.LIGHTYELLOW_EX}{keystone.__version__}{Fore.LIGHTRED_EX} is too old, minimum supported is {Fore.CYAN}{min_keystone}{Fore.RESET}")
        print(f"{Style.BRIGHT}Older Keystone Engine versions don't handle MIPS addresses correctly and will result in a bricked tablet when patching")
        return 1

    parser = CustomParser(allow_abbrev=False, formatter_class=CustomFormatter)

    parser.add_argument("code", help="Input ic901-code.bin, must be unmodified to avoid issues")
    parser.add_argument("--save-cfg", help="save .ini config using values in the firmware")
    parser.add_argument("--patch-cfg", help=f"patch firmware using .ini config, requires {Fore.CYAN}--output{Style.RESET_ALL} to be set")
    parser.add_argument("--output", help="Output patched ic901-code.bin")

    args = parser.parse_args()

    if not os.path.isfile(args.code):
        print(f"{Fore.LIGHTRED_EX}{args.code}: file doesn't exist")
        return 1

    if args.save_cfg: # save config file
        if args.patch_cfg is not None:
            print(f"{Fore.LIGHTRED_EX}Cannot set --patch-cfg when saving config")
            return 1

        if args.output is not None:
            print(f"{Fore.LIGHTRED_EX}Cannot set --output when saving config")
            return 1

        if not firmware_read(args.code):
            print(f"\n{Fore.LIGHTRED_EX}Failed to read firmware")
            return 1

        print("\nDisplaying values in firmware\n")
        firmware_info()

        cfg = load_config_fw()
        if not cfg:
            print(f"{Fore.LIGHTRED_EX}Failed to load firmware config")
            return 1

        save_config_ini(args.save_cfg, cfg)

        return 0
    elif args.patch_cfg:
        if args.save_cfg is not None:
            print(f"{Fore.LIGHTRED_EX}Cannot set --save-cfg when patching firmware")
            return 1

        if args.output is None:
            print(f"{Fore.LIGHTRED_EX}--patch-cfg requires --output to be set")
            return 1

        if not os.path.isfile(args.patch_cfg):
            print(f"{Fore.LIGHTRED_EX}{args.patch_cfg}: file doesn't exist")
            return 1

        if not firmware_read(args.code):
            print(f"\n{Fore.LIGHTRED_EX}Failed to read firmware")
            return 1

        cfgFileName = os.path.basename(args.patch_cfg)
        cfg = load_config_ini(args.patch_cfg)

        if not firmware_patch(args.code, args.output, cfg, cfgFileName):
            print(f"{Fore.LIGHTRED_EX}Failed to patch firmware")
            return 1

        if not firmware_read(args.output, silent=True):
            print(f"\n{Fore.LIGHTRED_EX}Failed to read patched firmware, DO NOT FLASH IT")
            return 1

        print(f"\nDisplaying NEW patched values in {Fore.LIGHTYELLOW_EX}{args.output}{Fore.RESET}\n")
        firmware_info()

        return 0

    parser.print_help()
    print(f"{Style.BRIGHT}{Fore.LIGHTYELLOW_EX}{os.path.basename(__file__)}: {Fore.LIGHTMAGENTA_EX}error:{Style.NORMAL} argument {Fore.CYAN}--save-cfg {Fore.LIGHTMAGENTA_EX}or {Fore.CYAN}--patch-cfg {Fore.LIGHTMAGENTA_EX}is required")
    return 1

if __name__ == "__main__":
    just_fix_windows_console()
    ret_code = main()

    print(Style.RESET_ALL)
    sys.exit(ret_code)
