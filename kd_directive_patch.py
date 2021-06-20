#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2015/3/6

__author__ = "TheKD"

import os
import idc
import logging
import commands
from idaapi import *


class blArray:
    def __init__(self):
        self.dwSrc = 0     # 原始地址
        self.dwDes = 0     # 目标地址
        self.lpRod = ''    # 汇编代码
        self.size = 0    # 指令大小
        self.dwOffset=0    # 相对偏移
        self.lable = ''    # 记录标签
        self.hexCode=''    # 记录字节码
class lableCls:
    def __init__(self):
        self.label=''
        self.dwAddr=0

class Patch_Arm_code_Dialog(Form):
    """Simple Form to test multilinetext and combo box controls"""
    def __init__(self, context=''):
        self.dialog_Place = r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
patch arm code
Please Input arm code
<input code:{txtMultiLineText}>
<##Address(hex)\::{mem_addr}>
"""
        if __EA64__:
            self.diglog_values = {
            'txtMultiLineText': Form.MultiLineTextControl(text=context),
            'mem_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
            }
        else:
            self.dialog_Place = self.dialog_Place + """
Option:
<Arm:{rArm}>
<Thumb:{rThumb}>{cGroup2}>
"""         
            self.diglog_values = {
            'txtMultiLineText': Form.MultiLineTextControl(text=context),
            'mem_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
            'cGroup2': Form.RadGroupControl(("rArm","rThumb")),
            }   
        Form.__init__(self, self.dialog_Place, self.diglog_values)
    def rundialog(self,inaddr = 0, inoption = 0):
        self.Compile()
        self.mem_addr.value= inaddr
        if not __EA64__:  
            self.cGroup2.value = inoption
        return self.Execute()
class KDArmPatch(object):
    def __init__(self, asPath, tmpDirPath):
        if __EA64__:
            self.asPath = asPath + os.sep + "aarch64-linux-android-as"
        else:
            self.asPath = asPath + os.sep + "arm-linux-androideabi-as"
        logging.debug(self.asPath)
        self.saveSpath = tmpDirPath + os.sep + "temparm01.s";
        self.saveOpath = tmpDirPath + os.sep + "temparm01.o";
        self.labelClsArray = []
        self.nCompilationType = 0   ##//用来记录是 arm 还是Thumb 汇编
        self.findCodeMaic='\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\xff\xff\xff\xff' ##// 用来定位代码的 maic
        self.address = 0
        self.inputArmCode=""
        self.armHeadCode="""
.globl _start
.align 2
_start:
.code {bit}
{armcode}
.byte 0x12,0x34,0x56,0x78,0x90,0x12,0x34,0x56,0x78,0x90,0x12,0x34,0xFF,0xFF,0xFF,0xFF
"""
        self.jmpDownCode="""
.globl _start
.align 2
_start:
.code {bit}
{armrod} asmgen
.org 0x{size}
asmgen:
"""
        self.jmpUpCode="""
.globl _start
.align 2
_start:
.code {bit}
asmgen:
.org 0x{size}
{armrod} asmgen
.byte 0x12,0x34,0x56,0x78,0x90,0x12,0x34,0x56,0x78,0x90,0x12,0x34,0xFF,0xFF,0xFF,0xFF
"""     
        self.armRegTables = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sp", "lr", "r10", "r11", "r12"]
        self.dialog = [
                    "STARTITEM 0",         #//让第一项获得焦点
                    "Offset",    #//窗口标题
                    "Please Input arm code",   #//文本内容
                    "<String input:t::>", #//一个16进制数
                    "<Addr   (hex):M:32:16::>", #//一个16进制数
                    ]
        ###### //当前文件编译出来 偏移到代码位置
        if __EA64__:
            self.elfCodeOffset = 0x40
        else:
            self.elfCodeOffset = 0x34
            ####### 如果 32 位的再出给单选框,让其选择是 Thumb 和arm
            self.dialog = self.dialog + [
                                "<##Option##Arm:R>",   #//给单选框提供组
                                "<Thumb:R>>"]
        pass
    def dailogInit(self,dialog):
        dialog_ui=""
        for str in dialog:
            dialog_ui += str
            dialog_ui += '\n'
        return dialog_ui
    def findVarilInfo(self, label):
        for labelObj in self.labelClsArray:
            if (labelObj.label == label):
                return labelObj
        return None
    def deleteKeyLines(self, armcode, key):
        retstr=''
        codelist=armcode.splitlines()
        for codestr in codelist:
            if(codestr.find(key) != 0):
                retstr += codestr
                retstr += '\n'
        return retstr
    def clac_b_directive(self, blObj):
        dwRange = max(blObj.dwDes,blObj.dwSrc) - min(blObj.dwDes,blObj.dwSrc)
        armcode = None
        retHexCode =None
        clacRange = 0
        index=0
        if(blObj.dwDes > blObj.dwSrc):
            armcode = self.jmpDownCode.format(bit= (2 - self.nCompilationType) * 16, armrod=blObj.lpRod, size='%x'%dwRange)
        else:
            ####//向上跳,要减去 本身质量的长度
            ### 如果是 Thumb 指令那么要判断一下  知否为 bl 的指令,如果是非 bl 指令那么只占两个字节
            # if(self.nCodeType and (len(blObj.lpRod) != 2 or blObj.lpRod[1].lower() != 'l')):
            #     clacRange = dwRange -2
            # else:
            #     clacRange = dwRange -4
            clacRange = dwRange
            armcode = self.jmpUpCode.format(bit= (2 - self.nCompilationType) * 16, armrod=blObj.lpRod, size='%x'%dwRange)
            if (0 == dwRange):
                armcode = self.deleteKeyLines(armcode, '.org')
        if __EA64__:
            ###// 删除 code 的标识
            armcode = self.deleteKeyLines(armcode, '.code')
        status,hexbuf = self.execAsArm(armcode)
        if(status == 0):
            index= 0
            ## //因为下面跳不存使用 魔术子, 因为存在一个空间问题,假设就向下跳 4个字节,那么我们就写不下 魔术字了, 所以这里直接使用指令的大小
            if(blObj.dwDes >= blObj.dwSrc):
                index = self.elfCodeOffset + blObj.size
            else:
                index = hexbuf.find(self.findCodeMaic)

            logging.debug("clac index: {0}".format(hex(index)))
            if(index >= 0):
                retHexCode = hexbuf[self.elfCodeOffset + clacRange:index]
        return retHexCode

    def getLabalToDesAddr(self, lable):
        if re.match('\A[0-9a-fxA-FX]+\Z',lable) is not None:
            return int(lable , 16)
        else:
            lableValue=self.findVarilInfo(lable)
            if(lableValue):
                return lableValue.dwAddr
            else:
                if(idc.BADADDR != get_name_ea(-1, lable)):
                    return get_name_ea(-1, lable)
        return None

    def AnalyzerStr(self,inputData, addr_ea):
        listCode = []
        armSum = 0;
        listBlArry=[]
        listarm = inputData.splitlines()
        for armstr in listarm:
            armstr=armstr.strip()
            if(len(armstr) > 0):
                if(armstr.find(':') >=0):
                    listCode.append(armstr)
                    locallable = lableCls()
                    locallable.label=armstr[0:armstr.find(':')].strip()
                    locallable.dwAddr= armSum * (2 - self.nCompilationType) * 2 + addr_ea
                    self.labelClsArray.append(locallable)
                    continue
                if __EA64__:
                    if(armstr[0] == 'B' or armstr[0] == 'b'):
                        spindex = armstr.find(' ')
                        lableStr = armstr[spindex:].strip()
                        if (len(armstr) > 2 and (armstr.lower()[1] == 'r' or armstr.lower()[2] == 'r')):
                            listCode.append(armstr)
                            armSum = armSum + 1
                        else:
                            localBl= blArray()
                            localBl.dwOffset = armSum * 2 * 2
                            localBl.dwSrc = addr_ea + localBl.dwOffset
                            localBl.lpRod = armstr[0:spindex].strip()
                            localBl.lable = lableStr.strip()
                            localBl.size = 4; ##//指令空间大小
                            listBlArry.append(localBl)
                            listCode.append('nop')
                            armSum = armSum + 1
                    else:
                        listCode.append(armstr)
                        armSum = armSum + 1
                else:
                    if(armstr[0] == 'B' or armstr[0] == 'b'):
                        spindex = armstr.find(' ')
                        lableStr = armstr[spindex:].strip()
                        if lableStr.lower() in self.armRegTables:
                            listCode.append(armstr)
                            armSum = armSum + 1
                        else:
                            localBl= blArray()
                            localBl.dwOffset = armSum * (2 - self.nCompilationType) * 2
                            localBl.dwSrc = addr_ea + localBl.dwOffset
                            localBl.lpRod = armstr[0:spindex].strip()
                            localBl.lable = lableStr.strip()
                            localBl.size = (2 - self.nCompilationType) * 2
                            listBlArry.append(localBl)
                            listCode.append('nop')
                            armSum = armSum + 1
                            ### //如果是Thumb 模式 的 bl 指令那么就要再加两个字符
                            if(self.nCodeType == 1 and len(localBl.lpRod) == 2 and (localBl.lpRod[1] == 'L' or localBl.lpRod[1] == 'l')):
                                armSum = armSum + 1
                                localBl.size += (2 - self.nCompilationType) * 2
                                listCode.append('nop')
                    else:
                        listCode.append(armstr)
                        armSum = armSum + 1
        for j in range(len(listBlArry)):
            listBlArry[j].dwDes = self.getLabalToDesAddr(listBlArry[j].lable)
            if(listBlArry[j].dwDes is None):
                errorcode="\nerror The wrong jump address!!\n armcode: " + str(listBlArry[j].lpRod) + ' ' + str(listBlArry[j].lable)
                raise StandardError(errorcode)
        return listCode,listBlArry

    ##### 输入arm指令代码返回 status 码还内容,如果执行正确那么返回 二进制流, 错误那么就返回错误信息
    def execAsArm(self, codeStr):
        hexbuf=None
        with open(self.saveSpath, "w") as f:
            f.write(codeStr)
            f.close()
        status,outbuf = commands.getstatusoutput("\"%s\" \"%s\" -o \"%s\""%(self.asPath,self.saveSpath,self.saveOpath))
        if(0 == status):
            f = open(self.saveOpath, 'rb')
            hexbuf = f.read()
            f.close()
        else:
            hexbuf=outbuf
            raise StandardError(outbuf)
        os.remove(self.saveSpath)
        os.remove(self.saveOpath)
        return status,hexbuf
    def prn_obj(self, obj): 
        print ','.join(['%s:%s' % item for item in obj.__dict__.items()])
    def replace_hex(self,srcStr,offset, desStr):
        return srcStr[0:offset] + desStr + srcStr[offset + len(desStr):]
    def getArmToHex(self, inputCode, addr_ea):
        rethex=''
        codelist, listBlArry=self.AnalyzerStr(inputCode, addr_ea)
        logging.debug("\n".join(codelist))
        #print "blArry",listBlArry.__dict__
        strcode=""
        for code in codelist:
            strcode +=code
            strcode +='\n'
        armcode = self.armHeadCode.format(bit=(2 - self.nCompilationType) * 16, armcode=strcode)
        if __EA64__:
            ###// 删除 code 的标识
            armcode = self.deleteKeyLines(armcode, '.code')
        status,hexbuf = self.execAsArm(armcode)
        if(0 == status):
            index = hexbuf.find(self.findCodeMaic)
            logging.debug("index: {0}".format(hex(index)))
            if(index >= 0):
                rethex = hexbuf[self.elfCodeOffset:index].encode('hex')
                logging.debug(rethex)
        else:
            print("arm error %s", hexbuf)
        for j in range(len(listBlArry)):
            listBlArry[j].hexCode=self.clac_b_directive(listBlArry[j]).encode('hex')
            self.prn_obj(listBlArry[j])
        for blObj in listBlArry:
            ##//因为将内存16进制 转化成了字符串所以 偏移都要 乘2
            rethex = self.replace_hex(rethex, blObj.dwOffset * 2, blObj.hexCode)
        return rethex

    def KDMain(self):
        #ti=textctrl_info_t(self.inputArmCode) #//默认值编辑框中的内容
        #ti.flags=0x4A
        self.nCompilationType = getSR(idc.ScreenEA(), str2reg("T"));
        self.address = idc.ScreenEA();
        #addresForm = Form.NumericArgument('M', value=self.address)
        #directiveRadioForm = Form.NumericArgument('N', value=self.nCompilationType)
        ti_obj = Patch_Arm_code_Dialog(self.inputArmCode)
        dingoStatus = ti_obj.rundialog(self.address, self.nCompilationType)
        # if __EA64__:
        #     dingoStatus = idaapi.AskUsingForm(self.dailogInit(self.dialog),
        #            pointer(c_void_p.from_address(ti.clink_ptr)),
        #            addresForm.arg)
        # else:
        #     dingoStatus = idaapi.AskUsingForm(self.dailogInit(self.dialog),
        #            ti.clink_ptr,
        #            addresForm.arg,
        #            directiveRadioForm.arg)
        if dingoStatus != 1:
            ti_obj.Free()
            print 'cancel patch!'
            return
        else:
            self.address = ti_obj.mem_addr.value
            if not __EA64__:
                self.nCodeType = ti_obj.cGroup2.value
        self.inputArmCode = ti_obj.txtMultiLineText.text
        ti_obj.Free()
        hexBuf = self.getArmToHex(self.inputArmCode, self.address)
        size = len(hexBuf) / 2
        print("arm patch  address:0x%08X, size: 0x%x"%(self.address, size))
        print ("input arm  code: \n%s"%self.inputArmCode)
        if idc.isLoaded(self.address) and idc.isLoaded(self.address + size - 1):
            readBuffer = idc.GetManyBytes(self.address, size, False)
            if(readBuffer is not None):
                print("==========arm code srcData==========")
                print readBuffer.encode('hex').upper()
            put_many_bytes(self.address, hexBuf.decode('hex'))
            print("==========arm code PatchData==========")
            print hexBuf
            print("=========arm code PatchSuccess========")
            ##//刷 ida 窗口
        refresh_idaview_anyway();
        

class KDArmPatchPlugins(plugin_t):
    flags=0
    wanted_name="KD arm patch plugins"
    wanted_hotkey="Meta-shift-space"
    comment="arm patch"
    help="Something helpful"
    def __init__(self):
        self.kdArmPatch = None
        pass
    def init(self):
        msg("Ida plugin arm patch init.\n")
        self.kdArmPatch = KDArmPatch(idaapi.idadir("plugins"), os.path.dirname(idc.GetIdbPath()))
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        self.kdArmPatch.KDMain()
def PLUGIN_ENTRY():
    return KDArmPatchPlugins()
# def main():
#     KDArmPatch(idaapi.idadir("plugins"), os.path.dirname(idc.GetIdbPath())).KDMain()
# main()