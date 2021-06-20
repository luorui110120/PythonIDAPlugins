#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: kd<thecjw@live.com>
# Created on 10:19 2015/3/6

__author__ = "TheCjw"

import os
import idc
from idaapi import *

def KDsuspendThreadMain():
    thread_Count = get_thread_qty()
    current_thread_id = get_current_thread()
    for i in range(thread_Count):
        if(current_thread_id != getn_thread(i)):
            suspend_thread(getn_thread(i))
            print("suspend thread: 0x%x" % getn_thread(i))
    
class KDsuspendThread(plugin_t):
    flags=0
    wanted_name="KDsuspendThread"
    wanted_hotkey="Meta-shift-t"
    comment="ida suspend other thread"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDsuspendThread init.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        KDsuspendThreadMain()
def PLUGIN_ENTRY():
    return KDsuspendThread()