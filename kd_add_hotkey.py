#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2020/11/12

__author__ = "TheCjw"

import os
import base64
from idaapi import *
from idc import *

def strToHexStr(strbuf):
    bytestrs = ""
    for c in strbuf:
        bytestrs += ('%02x' % ord(c))
    return bytestrs

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
        rv = idaapi.regval_t()
        if False == idaapi.get_reg_val(register, rv):
            return None
        current_addr = rv.ival
        return current_addr
    def JumpPrint(self, addr):
        Jump(addr)
        print("Jump 0x%x" % addr)
    def JumpDword(self):
        addr = ScreenEA();
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
        startaddr=GetFunctionAttr(ScreenEA(),FUNCATTR_START);
        Jump(startaddr);
    #### //跳到函数结尾
    def GotoCursorFuncEnd(self):
        endaddr=GetFunctionAttr(ScreenEA(),FUNCATTR_END);
        endaddr=FindCode(endaddr,SEARCH_UP);
        Jump(endaddr);
    def init_reg_hotkey(self):
        idaapi.add_hotkey("Meta-Shift-d", self.JumpDword)
        idaapi.add_hotkey("Meta-Shift-0", self.JumpR0) 
        idaapi.add_hotkey("Meta-Shift-1", self.JumpR1) 
        idaapi.add_hotkey("Meta-Shift-2", self.JumpR2) 
        idaapi.add_hotkey("Meta-Shift-3", self.JumpR3) 
        idaapi.add_hotkey("Meta-Shift-4", self.JumpR4)
        idaapi.add_hotkey("Meta-Shift-5", self.JumpR5)
        idaapi.add_hotkey("Meta-Shift-6", self.JumpR6)
        idaapi.add_hotkey("Meta-Shift-7", self.JumpR7)
        idaapi.add_hotkey("Meta-Shift-8", self.JumpR8) 
        idaapi.add_hotkey("Meta-Shift-9", self.JumpR9)
        idaapi.add_hotkey("Meta-Shift-s", self.JumpSP)
        idaapi.add_hotkey("Meta-Shift-l", self.JumpLR)
        idaapi.add_hotkey("Meta-Shift-p", self.JumpPC)
        idaapi.add_hotkey("Meta-[", self.GotoCursorFuncStart)
        idaapi.add_hotkey("Meta-]", self.GotoCursorFuncEnd)

def PLUGIN_ENTRY():
    return KDInit_addHotkey()