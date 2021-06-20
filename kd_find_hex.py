#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2020/11/6

import os
import idc
from idaapi import *

class KDFindHex(plugin_t):
    flags=0
    wanted_name="KDFindHex"
    wanted_hotkey="Meta-f"
    comment="ida memory patch bytes"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDPatchByte init.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        KDFindHex.main()

    
    @staticmethod
    def dailogInit():
        dialog = [
        "STARTITEM 0",         #//让第一项获得焦点
        "Feature code search",    #//窗口标题
        "The Feature Code Search Fuzzy Matching Use ? Replace"+ "\n"+\
        "Please enter the hexadecimal data size less 0x200",   #//文本内容
        "<HexStr:A:513:32::>",  # //第一项字符串数据
        "<StartAddr   (hex):M:32:16::>", #//一个16进制数
        "<EndAddr/Len (hex):M:32:16::>", #//一个16进制数
        "<##Option##EndAddr:R>",   #//给单选框提供组
        "<Len:R>>",       #//组内的第二个
        "<##Check Boxes##Jump to the first result:C>>",
        "<Set address to head of the section:C>>",
        "<Search all segments:C>>"
        ]
        dialog_ui=""
        for str in dialog:
            dialog_ui += str
            dialog_ui += '\n'
        return dialog_ui
    @staticmethod
    def searchReMatch(pattern, strbuf, baseAddr):
        listRet=[]
        searchbuf=strbuf
        index = 0;
        patternSize = len(pattern)
        strbufSize = len(strbuf)
        match = re.search(pattern,searchbuf)
        while(match is not None):
            if(match.start() % 2 == 0):
                listRet.append(baseAddr + (match.start() + index) / 2)
                index += match.start() + patternSize
            else:
                index += match.start() + 1
                if(index >= strbufSize):
                    break
            match = re.search(pattern,searchbuf[index:])
        return listRet

    @staticmethod
    def main():

        strInputHexBuf='';
        nStartAddr = idc.ScreenEA();
        nEndAddr = idc.SegEnd(nStartAddr);
        nSearchBufSize = 0;
        nEndTypeRadio = 0;
        bJmpFirst=1;
        bSetStartAddr=0;
        bSearchAllSegm=0;
        strSearchBuf=None;
        listSearchOut=[];

        strInputHexBufForm = Form.StringArgument(513)
        nStartAddrForm = Form.NumericArgument('M', value=nStartAddr)
        nEndAddrForm = Form.NumericArgument('M', value=nEndAddr)
        nEndTypeRadioForm = Form.NumericArgument('N', value=nEndTypeRadio)
        bJmpFirstForm = Form.NumericArgument('N', value=bJmpFirst)
        bSetStartAddrForm = Form.NumericArgument('N', value=bSetStartAddr)
        bSearchAllSegmForm = Form.NumericArgument('N', value=bSearchAllSegm)
        ok = idaapi.AskUsingForm(KDFindHex.dailogInit(),
                strInputHexBufForm.arg,
                nStartAddrForm.arg,
                nEndAddrForm.arg,
                nEndTypeRadioForm.arg,
                bJmpFirstForm.arg,
                bSetStartAddrForm.arg,
                bSearchAllSegmForm.arg,)
        if ok != 1:
            print 'Cancel Search Fuzzy Matching!'
            return
        else:
            strInputHexBuf=strInputHexBufForm.value
            nStartAddr=nStartAddrForm.value
            nEndAddr=nEndAddrForm.value
            nEndTypeRadio=nEndTypeRadioForm.value
            bJmpFirst=bJmpFirstForm.value
            bSetStartAddr=bSetStartAddrForm.value
            bSearchAllSegm=bSearchAllSegmForm.value
        #####变量初始化处理
        strInputHexBuf = strInputHexBuf.replace(' ','').replace('\n', '').replace('\r', '').upper()
        if nStartAddr > nEndAddr:
            Warning('Error !! EndAddr less StartAddr!')
            return
        if((len(strInputHexBuf) % 2) > 0):
            print "The data entered are not a multiple of two !!"
            print "Illegal characters: %s" % strInputHexBuf
            Warning("The data entered are not a multiple of two !!")
            return
        else:
            if re.match('\A[\?0-9\?a-fA-F]+\Z',strInputHexBuf) is None:
                print("The typed string is present in an illegal character!")
                print "Illegal characters: %s" % strInputHexBuf
                Warning("The typed string is present in an illegal character!")
                return
        ####################
        print("==========KDFindHex Start Search==========")
        if bSearchAllSegm == 0:
            if(bSetStartAddr == 1):
                nStartAddr = idc.SegStart(nStartAddr)
            if(nEndTypeRadio == 1):
                nSearchBufSize = nEndAddr
            else:
                nSearchBufSize = nEndAddr - nStartAddr
            print("search addr:0x%08X, size:0x%X, pattern:%s" %(nStartAddr, nSearchBufSize,strInputHexBuf))
            if idc.isLoaded(nStartAddr) and idc.isLoaded(nStartAddr + nSearchBufSize - 1):
                strSearchBuf = idc.GetManyBytes(nStartAddr, nSearchBufSize, False)
                if strSearchBuf is None:
                    print("read Search Buff Fail!")
                    return
                    ######## 正则表达式中 . 就是od中的?
                listSearchOut = KDFindHex.searchReMatch(strInputHexBuf.replace('?', '.'), strSearchBuf.encode('hex').upper(),nStartAddr)
            else:
                Warning('Error !! Invalid address!')
                return 
        else:
            print("search All Segm, pattern:%s" %(strInputHexBuf))
            segm = get_next_seg(0)
            ####### 正则表达式中 . 就是od中的?
            strInputHexBuf = strInputHexBuf.replace('?', '.')
            ###### //查询所有 段中的内容
            while( segm is not None ):
                buf = idc.GetManyBytes(segm.startEA, segm.size(), False)
                if(buf is not None):
                    listSearchOut += KDFindHex.searchReMatch(strInputHexBuf, buf.encode('hex').upper(),segm.startEA)
                segm = get_next_seg(segm.startEA)
        if len(listSearchOut) > 0 :
            if(bJmpFirst):
                jumpto(listSearchOut[0])
            print("==========Out List==========")
            for listaddr in listSearchOut:
                print("0x%8X" % listaddr)
        else:
            print("The match was not found !!!")
        print("=========Search END============")

def PLUGIN_ENTRY():
    return KDFindHex()