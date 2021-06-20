#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: kd<thecjw@live.com>
# Created on 10:19 2015/3/6

__author__ = "TheCjw"

import os
import idc
import pyperclip
from idaapi import *

def KDsendPerclipMain():
    addr = idc.ScreenEA();
    if addr > 0 :
        print "current addr: 0x%X" % addr
        pyperclip.copy('0x%X'% addr)
    
class KDsendPerclip(plugin_t):
    flags=0
    wanted_name="KDsendPerclip"
    wanted_hotkey="Meta-x"
    comment="ida send cur addr perclip"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDsendPerclip init.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        KDsendPerclipMain()
def PLUGIN_ENTRY():
    return KDsendPerclip()