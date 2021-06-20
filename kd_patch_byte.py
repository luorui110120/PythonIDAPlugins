#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2015/3/6

__author__ = "TheCjw"


import os
import idc
from idaapi import *

dialogKDPatchByte = [
"STARTITEM 0",         #//让第一项获得焦点
"Patch Data",    #//窗口标题
"Please enter the hexadecimal data size less 0x200",   #//文本内容
"<HexStr:A:513:32::>",  # //第一项字符串数据
"<Addr   (hex):M:32:16::>", #//一个16进制数
"<Count  (hex):M:32:16::>", #//一个16进制数
"<##Cover Or XorWrite##Write:R>",     #//覆盖写入或者疑惑写入
"<XorWrite:R>",       #//组内的第二个
"<CompulsoryWrite:R>>", #//强制 写入 代用 PatchByte 函数,在新生成的段也可以写入
"<##Serial Write##Byte:R>",   #//给单选框提供组
"<DWord:R>",        #//组内的第二个
"<QWord:R>>",        #//组内的第二个
"<##Check Boxes##Take the ScreenEA ignored addr:C>>"
]
def dailogInit(dialog):
    dialog_ui=""
    for str in dialog:
        dialog_ui += str
        dialog_ui += '\n'
    return dialog_ui


def strToList(strbuf):
    strByteList=[]
    for i in strbuf:
        strByteList.append(ord(i))
    return strByteList

def listToStr(listbyte):
    retstr=''
    for i in listbyte:
        retstr+=struct.pack("B",i)
    return retstr
def listCreate(listdata, size, fill):
    retListdata=[fill] * size
    count = min(len(listdata),size)
    for i in range(count):
        retListdata[i] = listdata[i]
    return retListdata
def listToSerial(listdata, few):
    index = 0;
    count = len(listdata) / few;
    tmplist=[None]*few
    for i in range(count):
        for j in range(few):
            tmplist[j]=listdata[i * few + j]
        tmplist.reverse();
        for k in range(few):
            listdata[i * few + k] = tmplist[k]
    return listdata
def listXorData(listdata1,listdata2):
    count = max(len(listdata1), len(listdata2)) 
    retListdata=listCreate(listdata1, count, 0)
    for i in range(count):
        retListdata[i]=retListdata[i] ^ listdata2[i]
    return retListdata

def strToHexStr(strbuf):
    bytestrs = ""
    for c in strbuf:
        bytestrs += ('%02X' % ord(c))
    return bytestrs
def readFile(path):
    f = open(path, 'rb')
    data = f.read()
    f.close()
    return data;

def KDPatchByteMain():

    nAddr = idc.ScreenEA();
    nCount = 1;
    size = 0;
    strBuf='';
    patchBuf='';
    checkStr='false'
    nPatchLogFlags = 1;
    serialRadioFormStr="byte";
    XorWriteRadioFormStr="Write"
    ##// 保存用户选择文件导入的方式
    openFilePath=''
    StrBufForm = Form.StringArgument(513)
    AddresForm = Form.NumericArgument('M', value=nAddr)
    CountForm = Form.NumericArgument('M', value=nCount)
    XorWriteRadioForm = Form.NumericArgument('N', value=0)
    SerialRadioForm = Form.NumericArgument('N', value=0)
    CheckForm = Form.NumericArgument('N', value=0)
    ok = idaapi.AskUsingForm(dailogInit(dialogKDPatchByte),
            StrBufForm.arg,
            AddresForm.arg,
            CountForm.arg,
            XorWriteRadioForm.arg,
            SerialRadioForm.arg,
            CheckForm.arg)
    if ok != 1:
        print 'cancel Patch!'
        return
    if CheckForm.value == 1:
        nAddr = idc.ScreenEA();
        checkStr = 'true'
    else:
        nAddr = AddresForm.value;
    nCount = CountForm.value
    #// 过滤特殊字符
    strBuf = StrBufForm.value
    strBuf = strBuf.replace(' ','').replace('\n', '').replace('\r', '')
    #// 如果长度为零那么就是通过文件导入的方式patch
    if(len(strBuf) == 0):
        openFilePath = idc.AskFile(0,"","OpenFile")
        if openFilePath is not None:
            strBuf=readFile(openFilePath)
        else:
            print 'cancel Patch!'
            return
    else:
        if((len(strBuf) % 2) > 0):
            print "Illegal characters: %s" % strBuf
            Warning("The data entered are not a multiple of two !!")
            return
        else:
            if re.match('\A[0-9a-fA-F]+\Z',strBuf) is None:
                print "Illegal characters: %s" % strBuf
                Warning("The typed string is present in an illegal character!")
                return
    if openFilePath =='':
        strBuf=strBuf.decode('hex')


    size=len(strBuf) * nCount
    #//将 buf 转化为 list  方便后面操作
    listbytes = strToList(strBuf)
    if(XorWriteRadioForm.value == 1):
        XorWriteRadioFormStr = "XorWrite"
    if(XorWriteRadioForm.value == 2):
        XorWriteRadioFormStr = "CompulsoryWrite"
    if SerialRadioForm.value == 1:
        listbytes=listToSerial(listbytes, 4)
        serialRadioFormStr = "DWord"
    if SerialRadioForm.value == 2:
        listbytes=listToSerial(listbytes, 8)
        serialRadioFormStr = "QWord"
    if(size > 0x200) :
        nPatchLogFlags = askyn_c(0,"Too much data may cause ida to die and print logs !!!");
    #/////对list进行序列化
    print("==============Input Src Data==============");
    print("Addr:0x%08X, Size:0x%X, Count:0x%X, WriteType:%s, Serial=%s, check=%s"%(nAddr, size, nCount, XorWriteRadioFormStr, serialRadioFormStr, checkStr))
    if(nPatchLogFlags):
        if openFilePath =='':
            print("hexadecimal data:")
            print(strToHexStr(strBuf))
        else:
            print("Patch In File Path: %s" %openFilePath)
    
    #// 是否需要翻倍list数据
    listbytes = listbytes * nCount
    
    if idc.isLoaded(nAddr) and idc.isLoaded(nAddr + size - 1):
        readBuffer = idc.GetManyBytes(nAddr, size, False)
        if(readBuffer is not None):
            if(nPatchLogFlags > 0):
                print("==========srcData==========")
                print strToHexStr(readBuffer)
            if(XorWriteRadioForm.value == 1):
                patchBuf = listToStr(listXorData(strToList(readBuffer),listbytes))
            else:
                patchBuf = listToStr(listbytes)
            put_many_bytes(nAddr, patchBuf)
            if(nPatchLogFlags > 0):
                print("==========PatchData==========")
                print strToHexStr(patchBuf)
            print("=========PatchSuccess========")
            ##//刷 ida 窗口
            refresh_idaview_anyway();
        else:
            print "get memory bytes error"
    elif(XorWriteRadioForm.value == 2):
        addr_index = 0
        for inbyte in listbytes:
            PatchByte(nAddr + addr_index, inbyte)
            addr_index += 1
    else: 
        print "Address error or length overflow !"

class KDPatchByte(plugin_t):
    flags=0
    wanted_name="KDPatchByte"
    wanted_hotkey="Meta-p"
    comment="ida memory patch bytes"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDPatchByte init.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        KDPatchByteMain()
def PLUGIN_ENTRY():
    return KDPatchByte()