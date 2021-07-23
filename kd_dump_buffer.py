#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2020/11/12

__author__ = "TheCjw"

import os
import idc
import platform
from idaapi import *

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QFileDialog

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
"<##Check Boxes##StartAddr set segm_start:C>>",
"<SendPerclip:C>>"
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

def ida_dump_ask_file(file_path, ea_addr, size, perclipCheck):
    savepath = ask_file(1, file_path, "sava path")
    if((savepath != None) and (1 == perclipCheck)):
        pyperclip.copy('%s' % savepath)
    dumpMemoryToFile(savepath, ea_addr, size)
def dumpMemoryToFile(savepath, ea_addr, size):
    if savepath is None:
        print "cancel dump!"
    else:
        buffer = idc.GetManyBytes(ea_addr, size, False)
        if buffer is not None:
            with open(savepath, "wb") as f:
                f.write(buffer)
                f.close()
                print("output addr:0x%08X, Size:0x%08X" % (ea_addr,size))
                print("Saved data success", savepath)
        else:
            print "get memory bytes error"


g_dumpUi = None

    ## 因为 ida 的bug, 目前只找到这种变扭的实现方式,不能在ida 主线程中调用ui的api;
def my_dump_qt5_ask_file(file_path, ea_addr, size, perclipCheck):
    class MyWindow(QtWidgets.QWidget):
        def __init__(self, file_path, ea_addr, size):
            super(MyWindow,self).__init__()
            self.myButton = QtWidgets.QPushButton(self)
            self.myButton.setObjectName("myButton")
            self.myButton.setText("Test")
            self.myButton.clicked.connect(self.msg)
            self.file_path = file_path
            self.ea_addr = ea_addr
            self.size = size
            self.perclip_flags = perclipCheck
            

        def msg(self):
            file_path, filetype = QFileDialog.getSaveFileName(self,
                                        "Dump memory",
                                        self.file_path,
                                        "Dump Files (*.Dump);;All Files (*)")   #设置文件扩展名过滤,注意用双分号间隔
            
            #print(fileName1,filetype)
            if len(file_path) > 0:
                dumpMemoryToFile(file_path, self.ea_addr, self.size)
                if(1 == self.perclip_flags):
                    pyperclip.copy('%s' % file_path)
            self.close()
    def action(add):
        add.myButton.click()
    global g_dumpUi
    if(None == g_dumpUi):
        g_dumpUi=MyWindow(file_path, ea_addr, size)
    g_dumpUi.resize(1,1)
    g_dumpUi.show()
    str_inages = (g_dumpUi,)
    t1 = threading.Thread(target=action,args=str_inages)
    t1.start()

def KDDataDumpMain():
    global g_dumpUi
    g_dumpUi = None
    nStartAddres = idc.ScreenEA();
    nEndAddres = idc.SegEnd(nStartAddres);
    size = 0;
    StartAddresForm = Form.NumericArgument('M', value=nStartAddres)
    EndAddresForm = Form.NumericArgument('M', value=nEndAddres)
    AddrRadioForm = Form.NumericArgument('N', value=0)
    OutRadioForm = Form.NumericArgument('N', value=0)
    SegCheckForm = Form.NumericArgument('N', value=0)
    PerclipCheckForm = Form.NumericArgument('N', value=0)
    ok = idaapi.AskUsingForm(dailogInit(dialogKDDataDump),
           StartAddresForm.arg,
           EndAddresForm.arg,
           AddrRadioForm.arg,
           OutRadioForm.arg,
           SegCheckForm.arg,
           PerclipCheckForm.arg)
    if ok != 1:
        print 'cancel dump!'
        return
    if SegCheckForm.value == 1:
        StartAddresForm.value = idc.SegStart(StartAddresForm.value)
    if AddrRadioForm.value == 0:
        size = EndAddresForm.value - StartAddresForm.value
    else:
        size = EndAddresForm.value
    
    if idc.isLoaded(StartAddresForm.value) and idc.isLoaded(StartAddresForm.value + size - 1) :
        if OutRadioForm.value == 0:
            strpath=os.path.dirname(idc.GetIdbPath()) + os.sep + "%08X-%08X.Dump"%(StartAddresForm.value, StartAddresForm.value + size)
            #savepath = idc.AskFile(1, strpath, "sava path")
            ##//为了兼容 mac 11.4版本
            if(platform.platform() == 'Darwin-20.5.0-x86_64-i386-64bit'):
                my_dump_qt5_ask_file(strpath, StartAddresForm.value, size, PerclipCheckForm.value)
            else:
                ida_dump_ask_file(strpath, StartAddresForm.value, size, PerclipCheckForm.value)
        else:
            buffer = idc.GetManyBytes(StartAddresForm.value, size, False)
            if buffer is not None:
                hexstr = strToHexStr(buffer)
                print("output addr:0x%08X, Size:0x%08X" % (StartAddresForm.value,size))
                print("=========hex=========")
                print(hexstr)
                print("=========end=========")
                if(1 == PerclipCheckForm.value):
                    pyperclip.copy('%s' % hexstr)
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