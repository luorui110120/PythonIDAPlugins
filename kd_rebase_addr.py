#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: TheCjw<thecjw@live.com>
# Created on 10:19 2015/3/6

__author__ = "TheCjw"

import os
import idc
from idaapi import *

dialogKDRebaseAddr = [
"STARTITEM 2",         #//让 base 获得焦点
"Rebase Addr",    #//窗口标题
"Please Input Addr",   #//文本内容
"<Old  (hex):M:32:16::>", #//一个16进制数
"<New  (hex):M:32:16::>", #//一个16进制数
"<Base (hex):M:32:16::>",
"<##Relative offset or Base addr##addr:R>",     #//覆盖写入或者疑惑写入
"<base:R>>",       #//组内的第二个
]
def dailogInit(dialog):
    dialog_ui=""
    for str in dialog:
        dialog_ui += str
        dialog_ui += '\n'
    return dialog_ui

def rebaseAddr(base):
    seglist =[];
    segstart = get_next_seg(0)
    while( segstart is not None ):
        seglist.append(segstart)
        segstart = get_next_seg(segstart.startEA)
    for i in range(len(seglist)):
        move_segm(seglist[i], get_fileregion_offset(seglist[i].startEA) + base, 0)
def rebaseAddrSuper(base):
    rebaseAddr(0)
    rebaseAddr(base)
def KDRebaseAddrMain():
    nOldAddr = idc.ScreenEA();
    nNewAddr = nOldAddr + 0x1000000;
    nBaseAddr = nOldAddr - get_fileregion_offset(nOldAddr);
    nOldBase = nBaseAddr
    bitType = 0xffffffff
    size = 0;
    OldAddresForm = Form.NumericArgument('M', value=nOldAddr)
    NewAddresForm = Form.NumericArgument('M', value=nNewAddr)
    BaseAddresForm = Form.NumericArgument('M', value=nBaseAddr)
    TypeRadioForm = Form.NumericArgument('N', value=1)
    ok = idaapi.AskUsingForm(dailogInit(dialogKDRebaseAddr),
           OldAddresForm.arg,
           NewAddresForm.arg,
           BaseAddresForm.arg,
           TypeRadioForm.arg)
    if ok != 1:
        print 'cancel RebaseAddr!'
        return
    if TypeRadioForm.value == 0:
        if idc.isLoaded(OldAddresForm.value):
            #rebase_program(NewAddresForm.value - OldAddresForm.value,MSF_FIXONCE)
            if __EA64__:
                bitType = 0xffffffffffffffff
            baseAddr =((NewAddresForm.value - OldAddresForm.value) & bitType) + nOldBase
            rebaseAddrSuper(baseAddr)
            print("RebaseAddr success, baseAddr: 0x%x" % (baseAddr))
        else:
            print "addr error!"
    else:
        rebaseAddrSuper(BaseAddresForm.value)
        print("RebaseAddr success, baseAddr: 0x%x" % BaseAddresForm.value)
    

class KDRebaseAddr(plugin_t):
    flags=0
    wanted_name="KDRebaseAddr"
    wanted_hotkey="Meta-shift-r"
    comment="ida RebaseAddr"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDRebaseAddr init.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        KDRebaseAddrMain()
def PLUGIN_ENTRY():
    return KDRebaseAddr()