#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2015/3/6

__author__ = "TheCjw"

import os
import idc
from idaapi import *

dialogKDDataDump = [
"STARTITEM 0",         #//让第一项获得焦点
"Dump Data",    #//窗口标题
"Please Input Addr",   #//文本内容
"<StartAddr   (hex):M:32:16::>", #//一个16进制数
"<EndAddr/Len (hex):M:32:16::>", #//一个16进制数
"<##Option##EndAddr:R>",   #//给单选框提供组
"<Len:R>>",       #//组内的第二个
"<##Output##File:R>",   #//给单选框提供组
"<Print:R>>",        #//组内的第二个
"<##Check Boxes##StartAddr set segm_start:C>>"
]
def dailogInit(dialog):
    dialog_ui=""
    for str in dialog:
        dialog_ui += str
        dialog_ui += '\n'
    return dialog_ui

def strToHexStr(strbuf):
    bytestrs = ""
    for c in strbuf:
        bytestrs += ('%02x' % ord(c))
    return bytestrs

def KDDataDumpMain():
    nStartAddres = idc.ScreenEA();
    nEndAddres = idc.SegEnd(nStartAddres);
    size = 0;
    StartAddresForm = Form.NumericArgument('M', value=nStartAddres)
    EndAddresForm = Form.NumericArgument('M', value=nEndAddres)
    AddrRadioForm = Form.NumericArgument('N', value=0)
    OutRadioForm = Form.NumericArgument('N', value=0)
    CheckForm = Form.NumericArgument('N', value=0)
    ok = idaapi.AskUsingForm(dailogInit(dialogKDDataDump),
           StartAddresForm.arg,
           EndAddresForm.arg,
           AddrRadioForm.arg,
           OutRadioForm.arg,
           CheckForm.arg)
    if ok != 1:
        print 'cancel dump!'
        return
    if CheckForm.value == 1:
        StartAddresForm.value = idc.SegStart(StartAddresForm.value)
    if AddrRadioForm.value == 0:
        size = EndAddresForm.value - StartAddresForm.value
    else:
        size = EndAddresForm.value
    
    if idc.isLoaded(StartAddresForm.value) and idc.isLoaded(StartAddresForm.value + size - 1) :
        if OutRadioForm.value == 0:
            strpath=os.path.dirname(idc.GetIdbPath()) + os.sep + "%08X-%08X.Dump"%(StartAddresForm.value, StartAddresForm.value + size)
            savepath = idc.AskFile(1, strpath, "sava path")
            if savepath is None:
                print "cancel dump!"
            else:
                buffer = idc.GetManyBytes(StartAddresForm.value, size, False)
                if buffer is not None:
                    with open(savepath, "wb") as f:
                        f.write(buffer)
                        f.close()
                        print("output addr:0x%08X, Size:0x%08X" % (StartAddresForm.value,size))
                        print("Saved data success", savepath)
                else:
                    print "get memory bytes error"
        else:
            buffer = idc.GetManyBytes(StartAddresForm.value, size, False)
            if buffer is not None:
                print("output addr:0x%08X, Size:0x%08X" % (StartAddresForm.value,size))
                print("=========hex=========")
                print(strToHexStr(buffer))
                print("=========end=========")
            else:
                print "get memory bytes error"
    else:
        print "addr error!"

class KDDataDump(plugin_t):
    flags=0
    wanted_name="KDDataDump"
    wanted_hotkey="Meta-d"
    comment="ida dump"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDDataDump init.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        KDDataDumpMain()
def PLUGIN_ENTRY():
    return KDDataDump()