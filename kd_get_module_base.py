#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2015/3/6

__author__ = "TheCjw"

import os
import idc
import pyperclip
from idaapi import *




dialogKDGetModuleBase = [
"STARTITEM 0",         #//让第一项获得焦点
"get module base",    #//窗口标题
"Please Input module name",   #//文本内容
"<name:A:513:32::>",
"<##Check Boxes##sendPerclip:C>>"
]
def dailogInit(dialog):
    dialog_ui=""
    for str in dialog:
        dialog_ui += str
        dialog_ui += '\n'
    return dialog_ui

def KDGetModuleBaseMain():
    nOffset = get_fileregion_offset(idc.ScreenEA());
    StrBufForm = Form.StringArgument(513)
    bsendPerclip = 1
    bsendPerclipForm = Form.NumericArgument('N', value=bsendPerclip)
    ok = idaapi.AskUsingForm(dailogInit(dialogKDGetModuleBase),
           StrBufForm.arg,
           bsendPerclipForm.arg)
    if ok != 1:
        print('cancel get module base!')
        return
    strBuf = StrBufForm.value
    strBuf = strBuf.replace(' ','').replace('\n', '').replace('\r', '')
    bsendPerclip = bsendPerclipForm.value
    gen=idc._get_modules()
    for li in gen:
        if( li.name.find(strBuf) >=0):
            print("name: " + li.name);
            print("base: 0x%x" %li.base);
            if(1 == bsendPerclip):
                pyperclip.copy('0x%X' % li.base)
            return
    print("find fail!!")

class KDGetModuleBase(plugin_t):
    flags=0
    wanted_name="KDGetModuleBase"
    wanted_hotkey="Meta-r"
    comment="ida KDGetModuleBase"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDGetModuleBase init.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        KDGetModuleBaseMain()
def PLUGIN_ENTRY():
    return KDGetModuleBase()