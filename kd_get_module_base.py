#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2015/3/6

__author__ = "TheCjw"

import os
import idc
import pyperclip
from idaapi import *

if IDA_SDK_VERSION == 720:
    __EA64__ = BADADDR == 0xFFFFFFFFFFFFFFFF
    IDAAPI_ScreenEA     = get_screen_ea
    IDAAPI_IsCode       = is_code
    IDAAPI_DelItems     = del_items
    IDAAPI_MakeCode     = create_insn
    IDAAPI_GetFlags     = get_full_flags
    IDAAPI_IsLoaded     = is_loaded
    IDAAPI_HasValue     = has_value
    IDAAPI_GetBptQty    = get_bpt_qty
    IDAAPI_GetBptEA     = idc.get_bpt_ea
    IDAAPI_GetBptAttr   = idc.get_bpt_attr
    IDAAPI_SegStart     = idc.get_segm_start
    IDAAPI_SegEnd       = idc.get_segm_end
    IDAAPI_GetBytes     = idc.get_bytes
    IDAAPI_AskYN        = idc.ask_yn
    IDAAPI_AskFile      = ask_file
    IDAAPI_AskLong      = ask_long
    IDAAPI_NextHead     = idc.next_head
    IDAAPI_GetDisasm    = lambda a, b: tag_remove(generate_disasm_line(a, b))
    IDAAPI_NextThat     = next_that
    IDAAPI_Jump         = jumpto
    # classes
    IDAAPI_Choose       = Choose
elif IDA_SDK_VERSION >= 700:
    # functions
    IDAAPI_ScreenEA     = get_screen_ea
    IDAAPI_IsCode       = is_code
    IDAAPI_DelItems     = del_items
    IDAAPI_MakeCode     = create_insn
    IDAAPI_GetFlags     = get_full_flags
    IDAAPI_SetColor     = set_color
    IDAAPI_IsLoaded     = is_loaded
    IDAAPI_HasValue     = has_value
    IDAAPI_GetBptQty    = get_bpt_qty
    IDAAPI_GetBptEA     = get_bpt_ea
    IDAAPI_GetBptAttr   = get_bpt_attr
    IDAAPI_SegStart     = get_segm_start
    IDAAPI_SegEnd       = get_segm_end
    IDAAPI_GetBytes     = get_bytes
    IDAAPI_AskYN        = ask_yn
    IDAAPI_AskFile      = ask_file
    IDAAPI_AskLong      = ask_long
    IDAAPI_NextHead     = next_head
    IDAAPI_GetDisasm    = lambda a, b: tag_remove(generate_disasm_line(a, b))
    IDAAPI_NextThat     = next_that
    IDAAPI_Jump         = jumpto
    # classes
    IDAAPI_Choose       = Choose
else:
    # functions
    IDAAPI_ScreenEA     = ScreenEA
    IDAAPI_IsCode       = isCode
    IDAAPI_DelItems     = MakeUnkn
    IDAAPI_MakeCode     = MakeCode
    IDAAPI_GetFlags     = getFlags
    IDAAPI_SetColor     = SetColor
    IDAAPI_IsLoaded     = isLoaded
    IDAAPI_HasValue     = hasValue
    IDAAPI_GetBptQty    = GetBptQty
    IDAAPI_GetBptEA     = GetBptEA
    IDAAPI_GetBptAttr   = GetBptAttr
    IDAAPI_SegStart     = SegStart
    IDAAPI_SegEnd       = SegEnd
    IDAAPI_GetBytes     = get_many_bytes
    IDAAPI_AskYN        = AskYN
    IDAAPI_AskFile      = AskFile
    IDAAPI_AskLong      = AskLong
    IDAAPI_NextHead     = NextHead
    IDAAPI_GetDisasm    = GetDisasmEx
    IDAAPI_NextThat     = nextthat
    IDAAPI_Jump         = Jump
    # classes
    IDAAPI_Choose       = Choose2



dialogKDGetModuleBase = [
"STARTITEM 0",         #//让第一项获得焦点
"get module base",    #//窗口标题
"Please Input module name",   #//文本内容
"<name:A:513:32::>",
"<##Check Boxes##sendPerclip:C>>",
"<jmpAddr:C>>"
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
    bsendPerclip = 0
    bsendPerclipForm = Form.NumericArgument('N', value=bsendPerclip)
    bJmpAddr = 1
    bJmpAddrForm = Form.NumericArgument('N', value=bJmpAddr)
    ok = AskUsingForm(dailogInit(dialogKDGetModuleBase),
           StrBufForm.arg,
           bsendPerclipForm.arg,
           bJmpAddrForm.arg)
    if ok != 1:
        print('cancel get module base!')
        return
    strBuf = StrBufForm.value
    strBuf = strBuf.replace(' ','').replace('\n', '').replace('\r', '')
    bsendPerclip = bsendPerclipForm.value
    bJmpAddr = bJmpAddrForm.value
    gen=idc._get_modules()
    for li in gen:
        if( li.name.find(strBuf) >=0):
            print("name: " + li.name);
            print("base: 0x%x" %li.base);
            if(1 == bsendPerclip):
                pyperclip.copy('0x%X' % li.base)
            if(1 == bJmpAddr):
                IDAAPI_Jump(li.base)
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