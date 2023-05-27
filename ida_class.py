import idautils
import idc
import idaapi
import ida_bytes

ida_path = ""

class utils:
    def get_seg_by_name(self,seg_name):
        for seg in idautils.Segments:
            if idc.get_segm_name(seg)==seg_name:
                return idc.get_segm_start(seg)
        return None

    #ea:数据地址 flag:交叉引用类型 type:是否是代码交叉引用    
    def get_xrefsto(self,ea,flag,type):
        result = list()
        for xref in idautils.XrefsTo(ea,1):
            if (flag == None or xref.type & flag) and (type == None or xref.iscode == type):
                list.append(xref.frm)
        return result
    
    def set_ins_nop(self,ea,size):
        if size == None:
            size = idc.next_head(ea) - ea
        for i in range(size):
            ida_bytes.patch_byte(ea+i,0x90)
        
    def set_call_nop(self):
        func_names = list("deamoe")

        for func_name in func_names:
            func_ea = idc.get_name_ea_simple(func_name)
            if func_ea != idc.BADADDR:
                ins_list = self.get_xrefsto(func_ea,None,True)
            for ins_ea in ins_list:
                if idc.print_insn_mnem(ins_ea) == "call":
                    self.set_ins_nop(ins_ea)
