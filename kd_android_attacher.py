#!/usr/bin/env python
# ! -*- coding: utf-8 -*-

import os

ADB_PATH = os.environ['HOME'] + os.sep +"Library" +os.sep + "Android" + os.sep + "sdk" + os.sep + "platform-tools" + os.sep + "adb"


def get_plugin_home():
    import inspect

    plugin_path = os.path.abspath(inspect.getfile(inspect.currentframe()))
    if os.path.islink(plugin_path):
        plugin_path = os.readlink(plugin_path)

    return os.path.dirname(plugin_path)


import sys

sys.path.append(get_plugin_home())

import idaapi
import idc

from aaf import utils


class KDAndroidAttacher(idaapi.plugin_t):
    ACTION_NAME = "Attach to Android app"

    flags = idaapi.PLUGIN_KEEP
    comment = ""
    wanted_name = "Android Debug Attach"
    wanted_hotkey = "Alt-F8"
    help = wanted_name + ": Debugger/" + ACTION_NAME

    def __init__(self):
        self.androidAttacher = None
        self.attaching = False
        pass

    def getSegmOffsetEndAddr(self):
        addr=0
        segstart = get_next_seg(0)
        while( segstart is not None ):
            if(get_fileregion_offset(segstart.endEA -1) >1):
                addr = segstart.endEA -1
            segstart = get_next_seg(segstart.startEA)
        return get_fileregion_offset(addr)
    def init(self):
        architecture = utils.getIdaArchitecture()
        if architecture != "arm":
            print "%s unsupported architecture: %s" % (self.wanted_name, architecture)
            return idaapi.PLUGIN_SKIP
        idc.Message("Initializing %s\n" % self.wanted_name)
        from aaf import adb
        wrapper = adb.AdbWrapper(ADB_PATH)
        from aaf import AndroidAttacher
        utilsJar = os.path.join(get_plugin_home(), "aaf", "utils.jar")
        config_name = "KDAndroidAttacher.conf"
        ######  getSegmOffsetEndAddr  获取最后一个有效地址的,用于保持配置文件,这样就不用生成文件了
        self.androidAttacher = AndroidAttacher(wrapper, utilsJar, config_name)
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg=0):
        if self.attaching:
            return

        try:
            if self.androidAttacher is not None:
                self.attaching = True
                self.androidAttacher.attach(arg)
        finally:
            self.attaching = False


def PLUGIN_ENTRY():
    return KDAndroidAttacher()
