#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: kd<thecjw@live.com>
# Created on 10:19 2015/3/6

__author__ = "TheKD"

import os
import idc
from idaapi import *

    
class KDsendRegT(plugin_t):
    if not __EA64__ :
        flags=idaapi.PLUGIN_KEEP
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
