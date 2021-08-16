#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: kd<thecjw@live.com>
# Created on 10:19 2015/3/6

__author__ = "TheKD"

import os
import idc
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

class KDsendRegT(plugin_t):
    if not __EA64__ :
        flags=PLUGIN_KEEP
        wanted_name="KDsendRegT"
        wanted_hotkey="Meta-t"
        comment="ida Converts the value of the current register T"
        help="Something helpful"

        def init(self):
            msg("Ida plugin KDsendRegT init.\n")
            return PLUGIN_OK
        def term(self):
            msg("Ida plugin term called.\n")
        def run(self,arg):
            self.KDMain()
        def KDMain(self):
            addr = idc.ScreenEA()
            old_reg_t = getSR(idc.ScreenEA(), str2reg("T"))
            new_reg_t = 0 if 1==old_reg_t else 1
            print("addr: 0x%08X, old_reg_t:%d, new_reg_t:%d" % (addr, old_reg_t, new_reg_t))
            idc.SetReg(idc.ScreenEA(), "T", new_reg_t)
def PLUGIN_ENTRY():
    return KDsendRegT()
