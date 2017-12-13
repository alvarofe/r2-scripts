"""
Author: Alvaro Felipe Melchor

This script has not been created on my own but rather based on FireEye script for
IDA Pro that you can read more about it in
https://www.fireeye.com/blog/threat-research/2017/03/introduction_to_reve.html

This script has been created to be used with radare2
"""


import os
import r2pipe

BADADDR = 0xFFFFFFFFFFFFFFFF

objcConst = None
objcSelRefs = None

refDict = {}
r2p = r2pipe.open()

info = r2p.cmdj('ij')

WORD_SIZE = 8
if 'bin' in info:
    WORD_SIZE = 8 if int(info["bin"]["bits"]) > 32 else 4

segments = r2p.cmdj('Sj')


def getRefPtr(classMethodsVA, objcSelRefs, objcMsgRefs, objcConst):
    ret = (None, None)
    namePtr = Qword(classMethodsVA)
    cnt = 0
    for x in XrefsTo(namePtr):
        if objcSelRefs and x >= objcSelRefs[0] and x < objcSelRefs[1]:
            ret = (False, x)
        elif objcMsgRefs and x >= objcMsgRefs[0] and x < objcMsgRefs[1]:
            ret = (True, x)
        elif objcConst and x >= objcConst[0] and x < objcConst[1]:
            cnt += 1    
    if cnt > 1:
        ret = (None, None)
    return ret



def buildRefs():
    global refDict
    for va in range(objcConst[0], objcConst[1], WORD_SIZE):
        xref_to = str(int(r2p.cmd('pv8 @ {0}'.format(va)), 16))
        if xref_to in refDict:
            refDict[xref_to].append(va)
        else:
            refDict[xref_to] = [va]
    for va in range(objcSelRefs[0], objcSelRefs[1], WORD_SIZE):
        xref_to = str(int(r2p.cmd('pv8 @ {0}'.format(va)), 16))
        if xref_to in refDict:
            refDict[xref_to].append(va)
        else:
            refDict[xref_to] = [va]

def XrefsTo(addr):
    try:
        return refDict[str(addr)]
    except:
        return []

def Xrefs(addr):
    refs = []
    xrefs = r2p.cmdj('axtj @ {}'.format(addr))  
    for x in xrefs:
        refs.append(int(x["from"]))
    return refs    

    

def Qword(addr):
    return int(r2p.cmd('pv8 @ {0}'.format(addr)), 16)

def Dword(addr):
    return int(r2p.cmd('pv4 @ {0}'.format(addr)), 16)

def invalidAddr(addr):
    if addr == BADADDR or addr == 0:
        return True
    return False    

def find_refs():
    size_DWORD = 4
    size_pointer = 8
    objcData = None
    objcMsgRefs = None
    objc2ClassSize = 0x28
    objc2ClassInfoOffs = 0x20
    objc2ClassMethSize = 0x18
    objc2ClassBaseMethsOffs = 0x20
    objc2ClassMethImpOffs = 0x10
    global objcConst
    global objcSelRefs
    total = 0
    print("[+] Parsing metadata in ObjC to find hidden xrefs")

    # iterate segments, grab the VAs we need
    for seg in segments:
        if "__objc_data" in seg["name"]:
            objcData = (seg["vaddr"], seg["vaddr"] + seg["vsize"])
        elif "__objc_selrefs" in seg["name"]:
            objcSelRefs = (seg["vaddr"], seg["vaddr"] + seg["vsize"])
        elif "__objc_msgrefs" in seg["name"]:
            objcMsgRefs = (seg["vaddr"], seg["vaddr"] + seg["vsize"])
        elif "__objc_const" in seg["name"]:
            objcConst = (seg["vaddr"], seg["vaddr"] + seg["vsize"])
    
    if ((objcSelRefs != None or objcMsgRefs != None) and (objcData != None and objcConst != None)) == False:
        print("could not find necessary Objective-C sections..\n")
        return
    buildRefs() 
    for va in range(objcData[0], objcData[1], objc2ClassSize):
        classRoVA = Qword(va + objc2ClassInfoOffs)
        if invalidAddr(classRoVA):
            continue
        classMethodsVA = Qword(classRoVA + objc2ClassBaseMethsOffs)
        if invalidAddr(classMethodsVA):
            continue
        count = Dword(classMethodsVA + size_DWORD)
        classMethodsVA += size_DWORD * 2 # advance to start of class methods array
        for va2 in range(classMethodsVA, classMethodsVA + objc2ClassMethSize * count, objc2ClassMethSize):
            isMsgRef, selRefVA = getRefPtr(va2, objcSelRefs, objcMsgRefs, objcConst)
            if selRefVA == None:
                continue
            funcVA = Qword(va2 + objc2ClassMethImpOffs)
            # adjust pointer to beginning of message_ref struct to get xrefs
            if isMsgRef:
                selRefVA -= size_pointer
            # add xref to func and change instruction to point to function instead of selref
            for x in Xrefs(selRefVA):
                r2p.cmd("axC {0} {1}".format(funcVA, x))
                total += 1 
    print('[+] A total of {0} xref were found'.format(total))

def analyze():
    print("[+] Analyzing searching references to selref")
    r2p.cmd('aar')
    #for arm we need emulation otherwise we are gonna miss references
    r2p.cmd('aae')

def beautify():
    for s in segments:
        if "__objc_selrefs" in s["name"]:
            start = s["vaddr"]
            end = start + s["size"]
            for i in range(start, end, WORD_SIZE):
                r2p.cmd("Cd 8 @ {0}".format(i))

analyze()
find_refs()
beautify()
