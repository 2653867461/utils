#include <pin.H>
#include <string>
#include <map>
#include <memory>
#include <vector>
#include <tuple>
#include <array>
#include <stdio.h>
#include <stddef.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <x86_64-linux-gnu/asm/unistd_64.h>


//可选开关
//日志文件名
KNOB< std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "f", "result.txt", "specify log file path");
//是否监控内存读写指令
KNOB< bool> KnobMem(KNOB_MODE_WRITEONCE, "pintool", "m", "0", "specify memory read write insert");
//是否监控系统调用指令
KNOB< bool> KnobSyscall(KNOB_MODE_WRITEONCE, "pintool", "s", "1", "specify syscall insert");
//是否监控call指令
KNOB< bool> KnobCall(KNOB_MODE_WRITEONCE, "pintool", "c", "1", "specify call insert");
//是否打印代码块信息
KNOB< bool> KnoBbl(KNOB_MODE_WRITEONCE, "pintool", "b", "0", "specify bbl insert");
//监控级别，1为只监控主模块的指令，0为全监控
KNOB< int> KnobInsLevel(KNOB_MODE_WRITEONCE, "pintool", "l", "0", "specify ins level");

//日志文件
FILE* new_stdout = NULL;

//主模块的内存边界
ADDRINT imageLow;	//IMG_LowAddress获取的是模块基址,IMG_HighAddress是代码段的末尾地址，不是模块末尾
ADDRINT imageHigh;	//不正确

//保存符号信息，根据地址解析符号名
class SymInfo {
public:
	SymInfo() {};

	void insert_syminfo(ADDRINT image, ADDRINT sym_b, ADDRINT sym_e, std::string sym_name) {
		if (sym_name.c_str()[0] == '.') {
			return;
		}
		std::tuple< ADDRINT, ADDRINT, std::string> item(sym_b, sym_e, sym_name);
		sym_info[image].push_back(item);
	};

	void insert_syminfo(ADDRINT addr, std::string name) {
		_sym_info[addr] = name;
	}

	ADDRINT find_symname_by_ip(ADDRINT image, ADDRINT ip, std::string& sym_name) {
		std::vector<std::tuple<ADDRINT, ADDRINT, std::string>>& sym_vector = sym_info[image];
		if (sym_vector.size() > 0) {
			for (auto sym_iter = sym_vector.begin(); sym_iter != sym_vector.end(); ++sym_iter) {
				if (ip >= std::get<0>(*sym_iter) && ip <= std::get<1>(*sym_iter)) {
					sym_name = std::get<2>(*sym_iter);
					return std::get<0>(*sym_iter);
				}
			}
		}
		auto iter = _sym_info.find(ip);
		if (iter != _sym_info.end()) {
			sym_name = iter->second;
			return iter->first;
		}

		return (ADDRINT)NULL;
	}
private:
	std::map<ADDRINT, std::string> _sym_info;
	std::map<ADDRINT, std::vector<std::tuple<ADDRINT, ADDRINT, std::string>>> sym_info;
};
class SymInfo SymInfoMgr;

/*
//反汇编模块 
#include<capstone/capstone.h>
class DisasmManage {
public:

	DisasmManage(cs_arch arch, cs_mode mode, FILE* _file) {
		file = _file;
		if (cs_open(arch, mode, &dis) != CS_ERR_OK) {
			fprintf(file, "error_info\t\tcs_open failed\n");
		}
	}

	~DisasmManage() {
		cs_close(&dis);
	}

	int disasm_buffer(uint9_t* buffer, size_t size, uint64_t address, cs_insn** insn, size_t nIns = 0) {
		int ret = cs_disasm(dis, buffer, size, address, nIns, insn);
		if (ret <= 0) { fprintf(file, "error_info\t\tcs_disam:%s\n", cs_strerror(cs_errno(dis))); }
		return ret;
	}

	void print_disasm(uint9_t* buffer, size_t size, uint64_t address, size_t nIns = 0) {
		cs_insn* cs_insasm = NULL;
		nIns = disasm_buffer(buffer, size, address, &cs_insasm, nIns);
		if (nIns > 0) {
			for (size_t i = 0; i < nIns; ++i) {
				fprintf(file, "disasm_info\t\tins_addr:0x%lx\tins_size:0x%x\tmnemonic:%s\toperand:%s\n", cs_insasm[i].address, cs_insasm[i].size, cs_insasm[i].mnemonic, cs_insasm[i].op_str);
			}
			cs_free(cs_insasm, nIns);
		}
	}
private:
	FILE* file;
	csh dis;
};

#ifdef x96_64
class DisasmManage DisasmMgr(CS_ARCH_X96, CS_MODE_64, new_stdout);
#elif x96
class DisasmManage DisasmMgr(CS_ARCH_X96, CS_MODE_32, new_stdout);
#endif //

*/
//内存读写
class mem_access;
class mem_cluster;
static ADDRINT WriteAddr;
static INT32 WriteSize;
std::map<ADDRINT, mem_access> shadow_mem;
std::vector<mem_cluster> clusters;
//脱壳
void check_ctransfer(ADDRINT src, ADDRINT dest);

class mem_access {
public:
	mem_access() :w(false), x(false), r(false), val(0) {};
	mem_access(bool ww, bool xx, bool rr, unsigned char v) : w(ww), x(xx), r(rr), val(v) {
	};
	bool w, x, r;
	unsigned char val;
};

class mem_cluster {
public:
	mem_cluster() :base(0), size(0), w(false), x(false), r(false) {};
	mem_cluster(ADDRINT b, INT32 s, bool ww, bool xx, bool rr) :base(b), size(s), w(ww), x(xx), r(rr) {
	};
	ADDRINT base;
	INT32 size;
	bool w, x, r;
};

VOID MemoryWriteEntry(ADDRINT addr, INT32 size) {
	WriteAddr = addr; WriteSize = size;
};

VOID MemoryWriteExit(VOID* ip) {
	ADDRINT addr = WriteAddr;
	for (ADDRINT i = addr; i < addr + WriteSize; i++) {
		shadow_mem[i].w = true;
		PIN_SafeCopy(&shadow_mem[i].val, (void*)i, 1);
	}
}

void check_ctransfer(ADDRINT src, ADDRINT dest) {
	mem_cluster clust;
	shadow_mem[dest].x = true;
	if (shadow_mem[dest].w == true) {
		fprintf(new_stdout, "warnning\t\tself_fix:0x%lx\n", dest);
	}
}

VOID MemoryReadRecord(VOID* ip, CHAR r, VOID* addr, INT32 size, BOOL isPrefetch) {

};

//提示与结束例程
INT32 print_usage();
VOID  print_result(INT32 code, VOID* v);

INT32 print_usage() {
	fprintf(new_stdout, "-------------------------------------------------------------\n");


	fprintf(new_stdout, "-------------------------------------------------------------\n");
	return -1;
}

VOID  print_result(INT32 code, VOID* v) {
	fprintf(new_stdout, "print_result\n");
	fclose(new_stdout);

}
//系统调用分析函数相关
class VirtualHandle;
class VirtualEnvironment;

#define VE_FD_FILE_TYPE 0
#define VE_FD_SOCKET_TYPE 1

//跟踪fd信息
class VirtualHandle {
public:
	VirtualHandle() {};
	VirtualHandle(std::string _name, int _type) : name(_name), type(_type) {};
	std::string get_name() { return name; };
	int get_type() { return type; };
private:
	std::string name;
	int type;
};
//管理fd
class VirtualEnvironment {
public:
	VirtualEnvironment() {
		handle_table[0] = VirtualHandle("STDIN", VE_FD_FILE_TYPE);
		handle_table[1] = VirtualHandle("STDOUT", VE_FD_FILE_TYPE);
		handle_table[2] = VirtualHandle("STDERR", VE_FD_FILE_TYPE);
	};
	~VirtualEnvironment() {};

	void set_fd(int fd, std::string name, int type) {
		handle_table[fd] = VirtualHandle(name, type);
	}
	std::string get_fd_name(int fd) {
		return handle_table[fd].get_name();
	};

	int get_fd_type(int fd) {
		return handle_table[fd].get_type();
	};

private:
	std::map<int, VirtualHandle> handle_table;
};

VirtualEnvironment VEMgr;
//系统调用回调函数,初始化在syscall_callback_init中
typedef void* (*SYSCALL_BEFORE_CALLBACK)(ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, CONTEXT* ctxt);
typedef void (*SYSCALL_AFTER_CALLBACK)(ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT ret, CONTEXT* ctxt, void* param);
std::map<ADDRINT, std::tuple< SYSCALL_BEFORE_CALLBACK, SYSCALL_AFTER_CALLBACK>> SyscallMonitor;

void after_openat(ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT ret, CONTEXT* ctxt, void* param) {
	fprintf(new_stdout, "syscall_openat\t\tfilename:%s\n", (char*)arg1);
	if (ret) {
		VEMgr.set_fd(ret, (char*)arg1, VE_FD_FILE_TYPE);
	}
}

void after_write(ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT ret, CONTEXT* ctxt, void* param) {
	if (VEMgr.get_fd_type(arg0) == VE_FD_FILE_TYPE || VEMgr.get_fd_type(arg0) == VE_FD_SOCKET_TYPE) {
		fprintf(new_stdout, "syscall_write\t\tfilename:%s\tsize:%lx\tbuffer:%s\n", VEMgr.get_fd_name(arg0).c_str(), ret, (char*)arg1);
	}
	else {
		fprintf(new_stdout, "syscall_write\t\tfd:%ld\tsize:%lx\tbuffer:%s\n", arg0, ret, (char*)arg1);
	}
}

void after_unlinkat(ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT ret, CONTEXT* ctxt, void* param) {
	fprintf(new_stdout, "syscall_unlink\t\tfilename:%s\n", (char*)arg1);
}

void after_connect(ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT ret, CONTEXT* ctxt, void* param) {
	fprintf(new_stdout, "syscall_connect\t\tfilename:%s\n", inet_ntoa(((sockaddr_in*)arg1)->sin_addr));
	if (ret) {
		VEMgr.set_fd(ret, inet_ntoa(((sockaddr_in*)arg1)->sin_addr), VE_FD_SOCKET_TYPE);
	}
}

void* before_execve(ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, CONTEXT* ctxt) {
	fprintf(new_stdout, "syscall_execve\t\tprocessspath:%s\targv:%s\n", (char*)arg0, (char*)arg1);
	return NULL;
}
#define SYSCALLL_CALLBACK_ITEM(nr,before,after) {SyscallMonitor[(nr)] = std::tuple< SYSCALL_BEFORE_CALLBACK, SYSCALL_AFTER_CALLBACK>{(before), (after)};}

void syscall_callback_init() {
	SYSCALLL_CALLBACK_ITEM(__NR_openat, NULL, after_openat);
	SYSCALLL_CALLBACK_ITEM(__NR_connect, NULL, after_connect)
	SYSCALLL_CALLBACK_ITEM(__NR_unlink, NULL, after_unlinkat);
	SYSCALLL_CALLBACK_ITEM(__NR_write, NULL, after_write);
	SYSCALLL_CALLBACK_ITEM(__NR_execve, before_execve, NULL);
};

//跟踪，关联syscall进入与返回
class syscall_info {
public:
	syscall_info() {};
	void insert_syscall_info(THREADID tid, std::array<ADDRINT, 9> param) {
		_syscall_info[tid] = param;
	};
	std::array<ADDRINT, 9> get_syscall_info(THREADID tid) {
		return _syscall_info[tid];
	};
private:
	std::map<THREADID, std::array<ADDRINT, 9>> _syscall_info;
};
class syscall_info SyscallInfo;

//示例代码中syscall有两个监控点，但在实践中SyscallCallbackType_INS_InsertCall没有命中过
typedef enum
{
	SyscallCallbackType_PIN_AddSyscallEntryFunction = 1,
	SyscallCallbackType_INS_InsertCall = 2
} SyscallCallbackType;

VOID SyscallEntry(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* param);
VOID SyscallExit(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* param);
VOID SysBefore(THREADID tid, ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT type0, CONTEXT* ctxt);
VOID SysAfter(THREADID tid, ADDRINT ret, CONTEXT* ctxt);

VOID SysBefore(THREADID tid, ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT type0, CONTEXT* ctxt) {
	void* opt = NULL;
	SYSCALL_BEFORE_CALLBACK before_callback = std::get<0>(SyscallMonitor[num]);
	if (before_callback != NULL) {
		opt = before_callback(arg0, arg1, arg2, arg3, arg4, arg5, ctxt);
	}
	std::array<ADDRINT, 9> param = { ip,num, arg0, arg1, arg2, arg3, arg4, arg5,(ADDRINT)opt };
	SyscallInfo.insert_syscall_info(tid, param);
}

VOID SysAfter(THREADID tid, ADDRINT ret, CONTEXT* ctxt)
{
	std::array<ADDRINT, 9> param = SyscallInfo.get_syscall_info(tid);
	SYSCALL_AFTER_CALLBACK before_callback = std::get<1>(SyscallMonitor[param[1]]);
	if (before_callback != NULL) {
		before_callback(param[2], param[3], param[4], param[5], param[6], param[7], ret, ctxt, (void*)param[8]);
	}
	fprintf(new_stdout, "syscall_info\t\ttid:0x%x\taddress:0x%lx\torder:0x%lx\treturn:0x%lx\n", tid, param[0], param[1], (unsigned long)ret);
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* param) {
	SysBefore(threadIndex, PIN_GetContextReg(ctxt, REG_INST_PTR), PIN_GetSyscallNumber(ctxt, std), PIN_GetSyscallArgument(ctxt, std, 0),
		PIN_GetSyscallArgument(ctxt, std, 1), PIN_GetSyscallArgument(ctxt, std, 2), PIN_GetSyscallArgument(ctxt, std, 3),
		PIN_GetSyscallArgument(ctxt, std, 4), PIN_GetSyscallArgument(ctxt, std, 5),
		(ADDRINT)SyscallCallbackType_PIN_AddSyscallEntryFunction, ctxt);
}

VOID SyscallExit(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* param) {
	SysAfter(threadIndex, PIN_GetContextReg(ctxt, static_cast<REG>(REG_INST_PTR)), ctxt);
}

//监控特定的函数调用的回调函数
typedef void* (*CALL_MONITOR_CALLBACK_BEFORE)(THREADID tid, ADDRINT src, ADDRINT dst, ADDRINT ret_ip, CONTEXT* ctxt);
typedef void(*CALL_MONITOR_CALLBACK_AFTER)(THREADID tid, ADDRINT src, ADDRINT dst, ADDRINT ret_ip, CONTEXT* ctxt, void* param);
std::map<ADDRINT, std::tuple<CALL_MONITOR_CALLBACK_BEFORE, CALL_MONITOR_CALLBACK_AFTER>> FuncCallMonitor;

//开始定义

//结束定义

//call指令分析
//关联call执行和返回
class call_info {
public:
	call_info() {};
	void insert_callinfo(THREADID tid, ADDRINT src, ADDRINT dst, ADDRINT ret, void* param) {
		_call_info[tid][ret] = std::tuple<ADDRINT, ADDRINT, void*>(src, dst, param);
	}
	std::tuple<ADDRINT, ADDRINT, void*> get_callinfo(THREADID tid, ADDRINT ret) {
		return _call_info[tid][ret];
	}
	//ret -> [src,dst]，根据返回地址关联
	std::map< THREADID, std::map<ADDRINT, std::tuple<ADDRINT, ADDRINT, void*>>> _call_info;
}CallInfo;

static void callAfter(ADDRINT ip, ADDRINT dst, CONTEXT* ctxt, THREADID tid);
static void retBefor(ADDRINT ip, ADDRINT dst, CONTEXT* ctxt, THREADID tid);

static void retBefor(ADDRINT ret_src, ADDRINT ret_dst, CONTEXT* ctxt, THREADID tid) {
	std::string src_name, dst_name; void* param = NULL;
	ADDRINT src_rtn_b = 0, dst_rtn_b = 0, ret_ip = 0, src = 0, dst = 0;

	std::tuple<ADDRINT, ADDRINT, void*> info = CallInfo.get_callinfo(tid, ret_dst);
	src = std::get<0>(info);
	dst = std::get<1>(info);
	param = std::get<2>(info);

	ret_ip = ret_dst;

	PIN_LockClient();
	IMG img_src = IMG_FindByAddress(src);
	IMG img_dst = IMG_FindByAddress(dst);
	PIN_UnlockClient();

	if (IMG_Valid(img_src)) {
		src_rtn_b = SymInfoMgr.find_symname_by_ip(IMG_LowAddress(img_src), src, src_name);
	}
	if (IMG_Valid(img_dst)) {
		dst_rtn_b = SymInfoMgr.find_symname_by_ip(IMG_LowAddress(img_dst), dst, dst_name);
	}
	if (src_rtn_b != (ADDRINT)NULL) {
		fprintf(new_stdout, "call_info\t\ttid:0x%x\tcall_src:%s\t%s+0x%lx(0x%lx)\t", tid, IMG_Name(img_src).c_str(), src_name.c_str(), src - src_rtn_b, src);
	}
	else {
		fprintf(new_stdout, "call_info\t\ttid:0x%x\tcall_src:0x%lx\t", tid, src);
	}

	if (dst_rtn_b != (ADDRINT)NULL) {
		fprintf(new_stdout, "call_dst:%s\t%s+0x%lx(0x%lx)\t", IMG_Name(img_dst).c_str(), dst_name.c_str(), dst - dst_rtn_b, dst);
	}
	else {
		fprintf(new_stdout, "call_dst:0x%lx\t", dst);
	}
	fprintf(new_stdout, "ret_src:0x%lx\tret_dst:0x%lx\trax:0x%lx\n", ret_src, ret_ip, PIN_GetContextReg(ctxt, REG_GAX));

	if (std::get<1>(FuncCallMonitor[dst]) != NULL) {
		std::get<1>(FuncCallMonitor[dst])(tid, src, dst, ret_ip, ctxt, param);
	}
}

static void callAfter(ADDRINT src, ADDRINT dst, CONTEXT* ctxt, THREADID tid) {
	ADDRINT ret_ip = 0;
	void* param = NULL;
	//保存call指令保存在stack上的返回地址，用于在ret指令处判断是哪个call函数返回了
	PIN_SafeCopy(&ret_ip, (void*)PIN_GetContextReg(ctxt, static_cast<REG>(REG_STACK_PTR)), sizeof(ADDRINT));
	if (std::get<0>(FuncCallMonitor[dst]) != NULL) {
		param = std::get<0>(FuncCallMonitor[dst])(tid, src, dst, ret_ip, ctxt);
	}
	CallInfo.insert_callinfo(tid, src, dst, ret_ip, param);

}


//插桩例程
static void instrument_trace(TRACE trace, void* param);
static void instrument_insn(INS ins, void* param);
static void ImageLoad(IMG img, void* param);

//IMAGE粒度的插桩例程
static void ImageLoad(IMG img, void* param) {

	if (IMG_Valid(img)) {
		if (IMG_IsMainExecutable(img)) {
			imageLow = IMG_LowAddress(img);
			imageHigh = IMG_HighAddress(img);
			SymInfoMgr.insert_syminfo(IMG_StartAddress(img), "EnrtyPoint");
		}
		fprintf(new_stdout, "ImageLoadEvent\t\tImageName:%s\tEntryPoint:0x%lx\tlow_addr:0x%lx\thigh_addr:0x%lx\t\n", IMG_Name(img).c_str(), IMG_EntryAddress(img), IMG_LowAddress(img), IMG_HighAddress(img));
		//fprintf(new_stdout,"raw_image_base:0x%lx  end:0x%lx\n", IMG_StartAddress(img), IMG_StartAddress(img) + IMG_SizeMapped(img));
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
				SymInfoMgr.insert_syminfo(IMG_LowAddress(img), RTN_Address(rtn), RTN_Address(rtn) + RTN_Size(rtn) - 1, RTN_Name(rtn));
				//fprintf(new_stdout,"func_info sym_name:%s sym_begain:0x%lx sym_end:0x%lx\n", RTN_Name(rtn).c_str(), RTN_Address(rtn), RTN_Address(rtn) + RTN_Size(rtn) -1 );
			}
		}
	}
}

//trace粒度插桩例程
static void instrument_trace(TRACE trace, void* param) {
	PIN_LockClient();
	IMG img = IMG_FindByAddress(TRACE_Address(trace));
	PIN_UnlockClient();
	if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) return;
	for (BBL bb = TRACE_BblHead(trace); BBL_Valid(bb); bb = BBL_Next(bb)) {
		fprintf(new_stdout, "bbl_info\t\tbbl_address:0x%lx\tbbl_size:0x%lx\n", BBL_Address(bb), BBL_Size(bb));
	}
}

//ins粒度插桩例程
static void instrument_insn(INS ins, void* param) {
	//检查是否是主模块
	//if (!(INS_Address(ins) >= imageLow) || !(INS_Address(ins) <= imageHigh) || !INS_Valid(ins)) 
	if (KnobInsLevel.Value() == 1) {
		if (!INS_Valid(ins)) {
			return;
		}
		IMG img = IMG_FindByAddress(INS_Address(ins));
		if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
			return;
		}
	}
	//控制流监控
	if (INS_IsControlFlow(ins)) {
		if (KnobSyscall.Value() && INS_IsSyscall(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore), IARG_THREAD_ID, IARG_INST_PTR, IARG_SYSCALL_NUMBER, IARG_SYSARG_VALUE, 0,
				IARG_SYSARG_VALUE, 1, IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3, IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE,
				5, IARG_ADDRINT, (ADDRINT)SyscallCallbackType_INS_InsertCall, IARG_CONTEXT, IARG_END);
		}

		if (KnobCall.Value()) {
			if (INS_IsCall(ins)) {
				INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)callAfter, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
			}
			if (INS_IsRet(ins)) {
				INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)retBefor, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
			}
		}

		if (KnobMem.Value() && INS_OperandCount(ins) > 0) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)check_ctransfer, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
		}
	}

	//内存读写监控
	if (KnobMem.Value() && INS_IsMemoryWrite(ins) && INS_IsStandardMemop(ins)) {
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MemoryWriteEntry, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
		if (INS_IsValidForIpointAfter(ins))
		{
			INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)MemoryWriteExit, IARG_INST_PTR, IARG_END);
		}
		if (INS_IsValidForIpointTakenBranch(ins))
		{
			INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)MemoryWriteExit, IARG_INST_PTR, IARG_END);
		}
	}
};

//pintool入口点
int main(int argc, char* argv[]) {
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) {
		print_usage();
		return true;
	}

	new_stdout = fopen(KnobOutputFile.Value().c_str(), "w+");
	if (new_stdout == NULL) {
		printf("error_info fopen failed errno:0x%x", errno);
	}
	syscall_callback_init();

	IMG_AddInstrumentFunction(ImageLoad, NULL);
	INS_AddInstrumentFunction(instrument_insn, NULL);
	if (KnoBbl.Value()) {
		TRACE_AddInstrumentFunction(instrument_trace, NULL);
	}
	if (KnobSyscall.Value()) {
		PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
		PIN_AddSyscallExitFunction(SyscallExit, NULL);
	}
	PIN_AddFiniFunction(print_result, NULL);

	PIN_StartProgram();
	return true;
}
