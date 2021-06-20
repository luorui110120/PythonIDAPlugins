#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2020/11/12

__author__ = "TheCjw"

import os
import idc
import subprocess
import base64
from idaapi import *

### 将数据写入到 粘贴版
def write_to_clipboard(output):
    process = subprocess.Popen(
        'pbcopy', env={'LANG': 'en_US.UTF-8'}, stdin=subprocess.PIPE)
    process.communicate(output.encode('utf-8'))
def strToHexStr(strbuf):
    bytestrs = ""
    for c in strbuf:
        bytestrs += ('%02x' % ord(c))
    return bytestrs
def readStr(addr):
    index=addr
    bytes = idc.GetManyBytes(index,1)
    str=''
    size=0
    if bytes is None:
        print "addr error !!" 
        return str,size
    while(bytes[0] != '\x00'):
        bytes = idc.GetManyBytes(index,1)
        if bytes is None:
            break
        if bytes[0] == '\x00':
            break
        str +=bytes[0]
        index = index + 1
    size = index-addr
    return str,size
def KDCopyStringMain():
    addr = idc.ScreenEA();
    if addr > 0 :
        str,size = readStr(addr)
        try:
            print "addr: 0x%08X, size:0x%x Content:%s" %(addr,size,str)
            write_to_clipboard(str.decode('utf-8'))
        except Exception as e:
        #    str = base64.b64encode(str)
        #    print("Illegal character set, which has been converted to base64 : %s" % str)
            str=strToHexStr(str)
            print("Illegal character set, print hex value: %s" % str)
            write_to_clipboard(str)
    else:
        print "addr error !"
    
class KDCopyString(plugin_t):
    flags=0
    wanted_name="KDCopyString"
    wanted_hotkey="Meta-i"
    comment="ida send cur addr perclip"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDCopyString init.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        KDCopyStringMain()
def PLUGIN_ENTRY():
    return KDCopyString()