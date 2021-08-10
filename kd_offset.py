#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2015/3/6

__author__ = "TheCjw"

import os
import idc
from idaapi import *




class ChooserForm(Form):
    def __init__(self, title, labels, values=None, cancel="Cancel", index=0, offset=0):
        Form.__init__(self, ("STARTITEM 0\n"
                             "BUTTON YES* OK\n"
                             "BUTTON CANCEL " + cancel + "\n" + title + "\n"
                             "\n"
                             "<##input offset(hex):{offset}>\n\n<Please select module:{values}>"),
                      {"offset":Form.NumericInput(tp=Form.FT_RAWHEX, value=offset),"values": Form.DropdownListControl(items=labels, readonly=True, selval=index)})
        self.labels = labels
        self.cvs = values if values is not None else labels

    def choose(self):
        self.Compile()
        ### 判断是否取消
        if (self.Execute() != 1):
            return None, None
        selected = self.values.value
        #### 获取 返回结果
        if(selected == -1):
            return None, self.offset.value
        else:
            return self.cvs[selected], self.offset.value
class module_item:
    def __init__(self):
        self.base=0
        self.size=0
        self.name=""
class KDOffset(plugin_t):
    flags=0
    wanted_name="KDOffset"
    wanted_hotkey="Meta-o"
    comment="ida KDOffset"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDOffset init.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        self.KDOffsetMain()
    ######### 插件代码
    def KDFindBase(self, modules_list, ea):
        for i in range(len(modules_list)):
            if (modules_list[i].base <= ea) and (ea < (modules_list[i].base + modules_list[i].size)):
                moname = idc.SegName(ea)
                if(modules_list[i].name.find(moname) >= 0 or
                    modules_list[i].name.find(moname.replace('_','-')) >= 0):
                    return i
        return -1
    def KDOffsetMain(self):
        key=[]
        values=[]
        courrent_ea = idc.ScreenEA()
        offset = 0
        ##// 获取所有模块
        gen=idc._get_modules()
        for li in gen:
            mitem = module_item()
            mitem.base = li.base
            mitem.size = li.size
            mitem.name = li.name
            values.append(mitem)
            key.append(li.name)
        listindex = self.KDFindBase(values, courrent_ea)
        if(listindex >= 0):
            offset = courrent_ea - values[listindex].base
        else:
            offset = get_fileregion_offset(courrent_ea)
            if(-1 == offset):
                offset = courrent_ea - get_imagebase()
        print("listindex: %d, ea: 0x%x,offset:0x%x" % (listindex, courrent_ea, offset))
        cho=ChooserForm("goto offset", key, values=values,index=listindex, offset= offset)
        modulesobj,offset = cho.choose()
        if offset != None:
            if modulesobj:
                print("name: %s \nbase: 0x%x  offset: 0x%x" %(modulesobj.name, modulesobj.base, offset))
                jumpto(modulesobj.base + offset)
            else:
                print("name: None offset: 0x%x" %(offset))
                ea_addr = get_fileregion_ea(offset)
                if(ea_addr == BADADDR):
                    ea_addr = offset + get_imagebase()
                jumpto(ea_addr)
        else:
            print("KDOffset cancel!!")
def PLUGIN_ENTRY():
    return KDOffset()