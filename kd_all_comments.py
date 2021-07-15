#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2015/3/6

from idaapi import *
import idautils
import idc
import base64
import json
from idaapi import Choose2

if IDA_SDK_VERSION >= 700:
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
KDShowAllCommentsFilterList = ['void', 'char', 'int', 'switch', 'jump', 'size_t', 'dw', 'hFile', 'lp', 'nSize', 'Alternative']
g_flags = True;
g_c = None
class chooser_handler_t(idaapi.action_handler_t):
    def __init__(self, thing):
        idaapi.action_handler_t.__init__(self)
        self.thing = thing

    def activate(self, ctx):
        #sel = []
        #for i in xrange(len(ctx.chooser_selection)):
        #    sel.append(str(ctx.chooser_selection.at(i)))
        #print "command %s selected @ %s" % (self.thing, ", ".join(sel))
        pass

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM


class MyChoose2(IDAAPI_Choose):

    def __init__(self, title, nb = 5, flags=0, width=None, height=None, embedded=False, modal=False):
        global g_flags
        self.n = 0
        self.icon = 5
        self.selcount = 0
        
        IDAAPI_Choose.__init__(
            self,
            title,
            [ ["Address", 16], ["T", 2], ["Instruction/Data", 60], ["Comment", 100],["Offset", 16]],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded
            )

        self.modal = modal
        #self.popup_names = [] #["Inzert", "Del leet", "Ehdeet", "Ree frech"]
        self.popup_names = [ "Filter", "Del", "Make", "" ]
        self.filter_list_name = "kd_all_comments_filter_list"
        self.filter_list=self.load_config(self.filter_list_name) if self.load_config(self.filter_list_name) else []
    #    print("self.filter_list" , self.filter_list)
        self.filter_snap_name = "kd_all_comments_filter_snap"
        self.filter_snap = self.get_filter_snap()
        self.items = self.get_all_comments() #[ self.make_item() for x in xrange(0, nb+1) ]
        
        #print("created %s" % str(self))

    def OnClose(self):
        pass
        #print "closed", str(self)

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"
        self.Refresh()
        return n
        #print("editing %d" % n)

    def OnInsertLine(self, n):
        #print("OnInsertLine %d" % n)
        #self.items.append(self.make_item())
        #self.items.append(self.filter_key())
        #print("insert line")
        #print("OnInsertLine n:",n)
        self.filter_key(n)
        self.Refresh()
        return n

    def OnSelectLine(self, n):
        self.selcount += 1
        ###//使用文件偏移,这样修改了 基地址 也可以条过去
        #print("n:%d, off:ox%x"%(n,int(self.items[n][4], 16)))
        #return n
        ea = get_fileregion_ea(int(self.items[n][4], 16))
        jumpto(ea)
        return n
        #Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        #print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        #print("getsize -> %d" % n)
        return n

    def OnDeleteLine(self, n):
        #print("del %d " % n)
        del self.items[n]
        self.Refresh()
        return n

    #def OnRefresh(self, n):
    #    print("refresh %d" % n)
        #self.filter_key(n)
        #self.Show(True)
        #test_choose2()
        #self.Show(False)
        #return n

    def OnGetIcon(self, n):#
        #print "geticon", n
        if(n >= 0):
            r = self.items[n]
            t = self.icon + r[1].count("*")
            return t
        #print "geticon", n, t
        return n

    def show(self):
        return self.Show(self.modal) >= 0

    def filter_key(self, n):
    #    print self.items[n][3]
        self.filter_list.append(self.items[n][3])
        self.save_config(self.filter_list_name,self.filter_list)
        filterlist = KDShowAllCommentsFilterList + self.filter_list
        listsize = len(self.items)
        listindexlist = []
        for listindex in range(listsize):
            if (self.items[listindex][3] in filterlist):
                listindexlist.append(listindex)
        listindex = len(listindexlist) - 1
        while(listindex > 0):
            del self.items[listindexlist[listindex]]
            #super().OnDeleteLine(listindexlist[listindex])
            self.Refresh()
            listindex = listindex - 1

    def make_item(self):
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r
    #### 将数据保存在数据库中
    def load_config(self, name):
    #    print("load_config name:%s" %name)
        idx = idc.GetArrayId(name)
        databuf=""
        if(idx != idc.BADADDR):
            i = 0
            configdata = idc.GetArrayElement(idc.AR_STR,idx,i)
            while (configdata and len(configdata) > 0):
                i = i + 1
                databuf = databuf + configdata
                configdata = idc.GetArrayElement(idc.AR_STR,idx,i)

            if(len(databuf) > 0):
            #    print("configdata", configdata, base64.b64decode(databuf))
                return json.loads(base64.b64decode(databuf))
        return None

    def save_config(self, name, listdata):
    #    print("save_config name:%s" %name, listdata)
        idx = idc.GetArrayId(name)
        if(idx == -1):
            idx = idc.CreateArray(name)
        if(idx != -1):
            databuf = base64.b64encode(json.dumps(listdata))
            count = len(databuf) / 512
            for i in range(count):
                idc.SetArrayString(idx,i, databuf[512*i:(i + 1)*512])
            if((len(databuf) % 512) > 0):
               return idc.SetArrayString(idx, count, databuf[count*512:])
            else:
                return True
        return False
    def check_isin_filter(self, cmt, offset):
        cmt_str = str(cmt)
        cmt_str = cmt_str.decode('utf-8')
        if(len(cmt_str.strip()) < 2):
            return True
        if(self.filter_snap and (offset in self.filter_snap)):
            return True
        filterLists=KDShowAllCommentsFilterList
        if(self.filter_list):
            filterLists = filterLists + self.filter_list
        for filter_str in filterLists:
            if(cmt_str.startswith(filter_str)):
                return True
        return False
    def create_filter_snap(self):
        self.filter_snap=[]
        for seg in idautils.Segments():
            #print 'Anylising:', idc.SegName(seg), hex(idc.SegStart(seg)), hex(idc.SegEnd(seg)) + '\n'
            ea = idc.SegStart(seg)
            start = idc.SegStart(seg)
            end = idc.SegEnd(seg)
            while ea < end:
                if ea != idc.BADADDR:
                    cmt = idc.GetCommentEx(ea, True)
                    cmt2 = idc.GetCommentEx(ea, False)
                    if cmt or cmt2:
                        self.filter_snap.append(get_fileregion_offset(ea))
                ea = idc.NextHead(ea, end)
        self.save_config(self.filter_snap_name, self.filter_snap)
        return self.filter_snap
    def get_filter_snap(self):
        print("get_filter_snap")
        self.filter_snap = self.load_config(self.filter_snap_name)
    #    print("self.filter_snap", self.filter_snap)
    #    if(len(self.filter_snap) == 0):
    #       ///建立快照,直接过滤系统所有的注释,方便查看直接的注释
    #        return self.create_filter_snap()
        return self.filter_snap
    def get_all_comments(self):
        cmts = []
        for seg in idautils.Segments():
            #print 'Anylising:', idc.SegName(seg), hex(idc.SegStart(seg)), hex(idc.SegEnd(seg)) + '\n'
            ea = idc.SegStart(seg)
            start = idc.SegStart(seg)
            end = idc.SegEnd(seg)
            while ea < end:

                if ea != idc.BADADDR:
                    cmt = idc.GetCommentEx(ea, True)
                    if cmt:
                        if self.check_isin_filter(cmt, get_fileregion_offset(ea)):
                            print "filter Address: ",format(ea, '#16X'),'In fliter,IGN:', cmt
                        else:
                            current_cmt = [format(ea, '#16X'), 'R', idc.GetDisasm(ea), cmt, format(get_fileregion_offset(ea), '#16X')]
                            cmts.append(current_cmt)
                            self.n += 1
                            #print " Address: ", format(ea, '#16X'), 'R', 'Comment:', cmt

                    cmt2 = idc.GetCommentEx(ea, False)
                    if cmt2:
                        print("cmt2",cmt2)
                        if self.check_isin_filter(cmt2, get_fileregion_offset(ea)):
                            print "filterEx2 Address: ",format(ea, '#16X'),'In fliter,IGN:', cmt2
                        else:
                            current_cmt = [format(ea, '#16X'), 'N', idc.GetDisasm(ea), cmt2, format(get_fileregion_offset(ea), '#16X')]
                            cmts.append(current_cmt)
                            self.n += 1
                            #print " Address: ",format(ea, '#16X'), 'N', 'Comment:', cmt2
                ea = idc.NextHead(ea, end)
        return cmts


    def OnGetLineAttr(self, n):
        pass
        #print("getlineattr %d" % n)
        #if n == 1:
        #    return [0xFF0000, 0]


 # -----------------------------------------------------------------------
def test_choose2(modal=False):
    global g_c
    #if(not g_c):
    g_c = MyChoose2("Comments List", nb=10, modal=modal)
    r = g_c.show()
    #c.get_all_comments() # get all comments
    # form = idaapi.get_current_tform()
    # for thing in ["A", "B"]:
    #     idaapi.attach_action_to_popup(form, None, "choose2:act%s" % thing)


# -----------------------------------------------------------------------
def test_choose2_embedded():
    global c
    c = MyChoose2("Comments List", nb=12, embedded=True, width=123, height=222)
    r = c.Embedded()
    if r == 1:
        try:
            if test_embedded:
                o, sel = _idaapi.choose2_get_embedded(c)
                print("o=%s, type(o)=%s" % (str(o), type(o)))
                test_embedded(o)
        finally:
            c.Close()


class show_cmts_plugin_t(idaapi.plugin_t):
    flags = 0
    wanted_name="KDShowAllComments"
    wanted_hotkey="Meta-;"
    comment="IDA Comments Viewer: generate all comments of the idb"
    help="Something helpful"

    def init(self):
        msg("Ida plugin KDShowAllComments init.\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print "Start to analyzing all comments in idb..."
    #    show_wait_box('Analyzing comments in progress, this will take a while.')
        test_choose2(False)
    #    hide_wait_box('Analyzing comments in progress, this will take a while.')
        print "Finished,have a good time"



    def term(self):
        hide_wait_box('Analyzing comments in progress, this will take a while.')





def PLUGIN_ENTRY():
    return show_cmts_plugin_t()