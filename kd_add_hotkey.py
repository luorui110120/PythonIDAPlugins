#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2020/11/12

__author__ = "TheCjw"

import os
import base64
import subprocess
from idaapi import *
import idc
from aaf import adb



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



ADB_PATH = os.environ['HOME'] + os.sep +"bin" +os.sep + "adb"
g_adb=adb.AdbWrapper(ADB_PATH)
g_config_file_path=idaapi.idadir("plugins") + "/kd_attach_config.txt"

def file_to_str(inpath):
    with open(inpath, 'rb') as fr:
        return fr.read()
    return None
def str_to_file(instr, inpath):
    with open(inpath, 'wb') as fw:
        fw.write(instr)
def strToHexStr(strbuf):
    bytestrs = ""
    for c in strbuf:
        bytestrs += ('%02x' % ord(c))
    return bytestrs
def off_to_ea(moduleName, offaddr):
    base = idc.GetFirstModule()
    while (base != None) and (idc.GetModuleName(base).find(moduleName) == -1):
        base = idc.GetNextModule(base)
    if base == None:
        print "failed to find module: " + moduleName
        return None
    else:
        return base + offaddr

def adb_process_name_to_pid(in_process_name):
    global g_adb
    ps = g_adb.callLostReturn(['shell', 'ps']).splitlines()
    for x in ps:
        xs = x.split()
        if in_process_name in xs:
            print xs
            pid=None
            for process in xs:
                if(None ==pid and process.isdigit()):
                    pid = int(process)
                if in_process_name == process:
                    return pid
    return None
def kd_attach(in_process_name=None, ip='localhost', ida_port=23946):
    global g_config_file_path
    pname = ''
    if(None == in_process_name):
        pname = file_to_str(g_config_file_path)
    else:
        pname = in_process_name
    pid=adb_process_name_to_pid(pname)
    if(None == pid):
        print('fail no process !!')
    else:
        idc.LoadDebugger("armlinux", use_remote=1)
        idc.SetRemoteDebugger(ip, "", ida_port)
        status = idc.AttachProcess(pid, -1)
        if(status >= 0):
            str_to_file(pname, g_config_file_path)
def kd_attach_config():
    global g_config_file_path
    print("attach config:%s"%file_to_str(g_config_file_path))

class KDInit_addHotkey(plugin_t):
    flags=0
    wanted_name="KDInit_addHotkey"
    wanted_hotkey=""
    comment="ida send cur addr perclip"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDInit_addHotkey init.\n")
        self.init_reg_hotkey()
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        msg("kdinit_hotkey\n")

    def my_get_reg_value(self, register):
        rv = regval_t()
        if False == get_reg_val(register, rv):
            return None
        current_addr = rv.ival
        return current_addr
    def JumpPrint(self, addr):
        
        print("Jump 0x%x, res:%r" % (addr,IDAAPI_Jump(addr)))
    def JumpDword(self):
        addr = IDAAPI_ScreenEA();
        if __EA64__:
            self.JumpPrint(Qword(addr));
        else:
            self.JumpPrint(Dword(addr));
    def JumpR0(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x0")
        else:
            lValue = self.my_get_reg_value("r0")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR0 error!")
    def JumpR1(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x1")
        else:
            lValue = self.my_get_reg_value("r1")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR1 error!")
    def JumpR2(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x2")
        else:
            lValue = self.my_get_reg_value("r2")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR2 error!")
    def JumpR3(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x3")
        else:
            lValue = self.my_get_reg_value("r3")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR3 error!")
    def JumpR4(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x4")
        else:
            lValue = self.my_get_reg_value("r4")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR4 error!")
    def JumpR5(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x5")
        else:
            lValue = self.my_get_reg_value("r5")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR5 error!")
    def JumpR6(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x6")
        else:
            lValue = self.my_get_reg_value("r6")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR6 error!")
    def JumpR7(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x7")
        else:
            lValue = self.my_get_reg_value("r7")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR7 error!")
    def JumpR8(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x8")
        else:
            lValue = self.my_get_reg_value("r8")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR8 error!")
    def JumpR9(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x9")
        else:
            lValue = self.my_get_reg_value("r9")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getR9 error!")
    def JumpR10(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x10")
        else:
            lValue = self.my_get_reg_value("r10")
        if(None != lValue):
            self.JumpPrint(lValue);
        else:
            print("getR10 error!")
    def JumpR11(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x11")
        else:
            lValue = self.my_get_reg_value("r11")
        if(None != lValue):
            self.JumpPrint(lValue);
        else:
            print("getR11 error!")
    def JumpSP(self):
        if __EA64__:
            lValue = self.my_get_reg_value("sp")
        else:
            lValue = self.my_get_reg_value("sp")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getSP error!")
    def JumpLR(self):
        if __EA64__:
            lValue = self.my_get_reg_value("x30")
        else:
            lValue = self.my_get_reg_value("lr")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getLR error!")
    def JumpPC(self):
        if __EA64__:
            lValue = self.my_get_reg_value("pc")
        else:
            lValue = self.my_get_reg_value("pc")
        if(None != lValue):
	        self.JumpPrint(lValue);
        else:
            print("getPC error!")
        ## //跳到函数开头
    def GotoCursorFuncStart(self):
        startaddr=idc.GetFunctionAttr(IDAAPI_ScreenEA(),idc.FUNCATTR_START);
        IDAAPI_Jump(startaddr);
    #### //跳到函数结尾
    def GotoCursorFuncEnd(self):
        endaddr=idc.GetFunctionAttr(IDAAPI_ScreenEA(),idc.FUNCATTR_END);
        endaddr=idc.FindCode(endaddr,SEARCH_UP);
        IDAAPI_Jump(endaddr);
    def OpenCurrentDir(self):
        subprocess.check_output('open .',shell=True)
    def init_reg_hotkey(self):
        add_hotkey("Meta-Shift-d", self.JumpDword)
        add_hotkey("Meta-Shift-0", self.JumpR0) 
        add_hotkey("Meta-Shift-1", self.JumpR1) 
        add_hotkey("Meta-Shift-2", self.JumpR2) 
        add_hotkey("Meta-Shift-3", self.JumpR3) 
        add_hotkey("Meta-Shift-4", self.JumpR4)
        add_hotkey("Meta-Shift-5", self.JumpR5)
        add_hotkey("Meta-Shift-6", self.JumpR6)
        add_hotkey("Meta-Shift-7", self.JumpR7)
        add_hotkey("Meta-Shift-8", self.JumpR8) 
        add_hotkey("Meta-Shift-9", self.JumpR9)
        add_hotkey("Meta-Shift-a", self.JumpR10)
        add_hotkey("Meta-Shift-b", self.JumpR11)
        add_hotkey("Meta-Shift-s", self.JumpSP)
        add_hotkey("Meta-Shift-l", self.JumpLR)
        add_hotkey("Meta-Shift-p", self.JumpPC)
        add_hotkey("Meta-[", self.GotoCursorFuncStart)
        add_hotkey("Meta-]", self.GotoCursorFuncEnd)
        add_hotkey("Meta-Shift-o", self.OpenCurrentDir)

def PLUGIN_ENTRY():
    return KDInit_addHotkey()