#include "MyPinTool.h"

KNOB< std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "f", "result.txt", "specify log file path");

//日志文件
FILE* new_stdout = NULL;

//主模块的内存边界
ADDRINT imageLow;	
ADDRINT imageHigh;	

//SymInfo相关定义
SymInfo SymInfoMgr;

void SymInfo::insert_syminfo(ADDRINT image, ADDRINT sym_b, ADDRINT sym_e, std::shared_ptr<std::string> sym_name) {
	if (sym_name->c_str()[0] == '.') {
		return;
	}
	sym_info[image].push_back(SymInfoType(sym_b, sym_e, sym_name));
};

ADDRINT SymInfo::query_syminfo(ADDRINT image, ADDRINT ip, std::shared_ptr<std::string>& sym_name) {
	std::vector<SymInfoType>& sym_vector = sym_info[image];
	if (sym_vector.size() > 0) {
		for (auto sym_iter = sym_vector.begin(); sym_iter != sym_vector.end(); ++sym_iter) {
			if (ip >= std::get<0>(*sym_iter) && ip <= std::get<1>(*sym_iter)) {
				sym_name = std::get<2>(*sym_iter);
				return std::get<0>(*sym_iter);
			}
		}
	}
	return (ADDRINT)NULL;
}

ADDRINT SymInfo::query_syminfo(ADDRINT ip, std::shared_ptr<std::string>& sym_name) {
	PIN_LockClient();
	IMG img = IMG_FindByAddress(ip);
	PIN_UnlockClient();

	if (IMG_Valid(img)) {
		return query_syminfo(IMG_LowAddress(img), ip, sym_name);
	}
	return (ADDRINT)NULL;
}

//函数调用相关监控定义
std::map<ADDRINT, std::tuple<CALL_MONITOR_CALLBACK_BEFORE, CALL_MONITOR_CALLBACK_AFTER>> FuncCallMonitor;
CallTraceInfo callTraceInfoMgr;

void CallTraceInfo::insert_callinfo(THREADID tid, ADDRINT src_ip, ADDRINT dst_ip, ADDRINT ret_dst) {
	LOG_INFO("call_ins:\tcall_src%lx\tcall_dst:%lx\n", src_ip, dst_ip);
	call_trace_info[tid][ret_dst].push(CallTraceInfoType(src_ip, dst_ip, (ADDRINT)NULL));
}

CallTraceInfo::CallTraceInfoType CallTraceInfo::query_callinfo(THREADID tid, ADDRINT ret_src, ADDRINT ret_dst) {
	LOG_INFO("ret_ins:\tret_src:%lx\tret_dst:%lx\n", ret_src, ret_dst);
	std::stack<CallTraceInfo::CallTraceInfoType>& stack_ref= call_trace_info[tid][ret_dst];
	if (stack_ref.size() == 0) {
		return CallTraceInfo::CallTraceInfoType((ADDRINT)NULL, (ADDRINT)NULL, (ADDRINT)NULL);
	}
	return stack_ref.top();
}

void CallTraceInfo::pop_callinfo(THREADID tid, ADDRINT ret_src, ADDRINT ret_dst) {
	std::stack<CallTraceInfo::CallTraceInfoType>& stack_ref = call_trace_info[tid][ret_dst];
	if (stack_ref.size() != 0) {
		stack_ref.pop();
	}
	return;
}

static void callAfter(ADDRINT ip, ADDRINT dst, CONTEXT* ctxt, THREADID tid) {
	ADDRINT ret_dst = 0;
	PIN_SafeCopy(&ret_dst, (void*)PIN_GetContextReg(ctxt, static_cast<REG>(REG_STACK_PTR)), sizeof(ADDRINT));
	CallTraceInfoMgr.insert_callinfo(tid, ip, dst, ret_dst);
	DEBUG_INFO("call_ins_info:\tcall_src:%lx\tcall_dst:%lx\n", ip, dst);
	if (std::get<0>(FuncCallMonitor[dst]) != NULL) {
		std::get<0>(FuncCallMonitor[dst])(tid, ip, dst, ctxt);
	}
}

static void retBefor(ADDRINT ret_src, ADDRINT ret_dst, CONTEXT* ctxt, THREADID tid) {
	std::shared_ptr<std::string> src_name, target_name;
	ADDRINT src_rtn_b = 0 ,call_src = 0, call_dst = 0;

	CallTraceInfo::CallTraceInfoType info = CallTraceInfoMgr.query_callinfo(tid, ret_src, ret_dst);
	call_src = std::get<0>(info);
	call_dst = std::get<1>(info);

	if (call_src == NULL) {
		LOG_INFO("unexcept_call_info:\t无关联的call调用信息，异常控制流\t");
		goto ret_info;
	}

	src_rtn_b = SymInfoMgr.query_syminfo(call_src, src_name);
	if (src_rtn_b != (ADDRINT)NULL) {
		LOG_INFO("call_info:\ttid:0x%x\tcall_src:%s+0x%lx(0x%lx)\t", tid, src_name->c_str(), call_src - src_rtn_b, call_src);
	}
	else {
		LOG_INFO("call_info:\ttid:0x%x\tcall_src:0x%lx\t", tid, call_src);
	}

	if (SymInfoMgr.query_syminfo(call_dst, target_name) != NULL) {
		LOG_INFO("call_dst:%s(0x%lx)\t", target_name->c_str(),call_dst);
	}
	else {
		LOG_INFO("call_dst:0x%lx\t", call_dst);
	}

ret_info:
	LOG_INFO("ret_src:0x%lx\t", ret_src);
	LOG_INFO("ret_dst:0x%lx\t", ret_dst);
	LOG_INFO("rax:0x%lx\n", PIN_GetContextReg(ctxt, REG_GAX));

	if (std::get<1>(FuncCallMonitor[call_dst]) != NULL) {
		std::get<1>(FuncCallMonitor[call_dst])(tid, call_src, call_dst, ret_src, ret_dst, ctxt);
	}
	CallTraceInfoMgr.pop_callinfo(tid, ret_src, ret_dst);
}

void call_callback_init() {
	//定义call回调函数
}

//系统调用相关定义
SyscallTraceInfo SyscallTraceInfoMgr;
std::map<ADDRINT, std::tuple<SYSCALL_MONITOR_CALLBACK_BEFORE, SYSCALL_MONITOR_CALLBACK_AFTER>> SyscallCallMonitor;

void syscall_callback_init() {
	SYSCALL_CALLBLACK_ITEM(__NR_openat, NULL, after_openat);
}

void SyscallTraceInfo::insert_syscall_info(THREADID tid, ADDRINT order, ADDRINT src, ADDRINT param){
	syscall_trace_info[tid] = SyscallTraceInfoType(order, src, param);
};

SyscallTraceInfo::SyscallTraceInfoType& SyscallTraceInfo::query_syscall_trace_info(THREADID tid) {
	return syscall_trace_info[tid];
};

void SyscallEntry(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std,void* param) {
	ADDRINT order = PIN_GetSyscallNumber(ctxt, std);
	SYSCALL_MONITOR_CALLBACK_BEFORE before = std::get<0>(SyscallCallMonitor[order]);
	SyscallTraceInfoMgr.insert_syscall_info(threadIndex, order, PIN_GetContextReg(ctxt, REG_INST_PTR), (ADDRINT)NULL);
	if (before != NULL) {
		before(threadIndex, ctxt, std);
	}
}
void SyscallExit(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, void* param) {
	SyscallTraceInfo::SyscallTraceInfoType param = (SyscallTraceInfoMgr.query_syscall_trace_info(threadIndex));
	ADDRINT order = std::get<0>(param);
	ADDRINT src = std::get<1>(param);
	ADDRINT ret = PIN_GetSyscallReturn(ctxt, std);

	SYSCALL_MONITOR_CALLBACK_BEFORE after = std::get<1>(SyscallCallMonitor[order]);
	if (after != NULL) {
		after(threadIndex, ctxt, std);
	}
	LOG_INFO("syscall_info:\taddress:0x%lx\torder:0x%lx\treturn:0x%lx\n", src, order, ret);
}

//IMAGE粒度的插桩例程
static void ImageLoad(IMG img, void* param) {

	if (IMG_Valid(img)) {
		if (IMG_IsMainExecutable(img)) {
			imageLow = IMG_LowAddress(img);
			imageHigh = IMG_HighAddress(img);
			SymInfoMgr.insert_syminfo(imageLow, IMG_StartAddress(img), IMG_StartAddress(img),std::make_shared<std::string>("main_module_start"));
		}
		LOG_INFO("ImageLoadEvent:\tImageName:%s\tEntryPoint:0x%lx\tlow_addr:0x%lx\thigh_addr:0x%lx\t\n", IMG_Name(img).c_str(), IMG_EntryAddress(img), IMG_LowAddress(img), IMG_HighAddress(img));
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
				SymInfoMgr.insert_syminfo(IMG_LowAddress(img), RTN_Address(rtn), RTN_Address(rtn) + RTN_Size(rtn) - 1, std::make_shared<std::string>(RTN_Name(rtn)));
				DEBUG_INFO("func_info sym_name:%s sym_begain:0x%lx sym_end:0x%lx\n", RTN_Name(rtn).c_str(), RTN_Address(rtn), RTN_Address(rtn) + RTN_Size(rtn) -1 );
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
		LOG_INFO("bbl_info:\tbbl_address:0x%lx\tbbl_size:0x%lx\n", BBL_Address(bb), BBL_Size(bb));
	}
}

//ins粒度插桩例程
static void instrument_insn(INS ins, void* param) {
	//检查是否是主模块
	IMG img = IMG_FindByAddress(INS_Address(ins));
	if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
		return;
	}
	
	//控制流监控
	if (INS_IsControlFlow(ins)) {
		if (INS_IsCall(ins)) {
			INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)callAfter, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
		}
		if (INS_IsRet(ins)) {
			INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)retBefor, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
		}
	}

};

//Pintool模块的入口点函数
int main(int argc, char* argv[]) {
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) {
		return true;
	}

	new_stdout = fopen(KnobOutputFile.Value().c_str(), "w+");

	if (new_stdout == NULL) {
		printf("error_info fopen failed errno:0x%x", errno);
		exit(1);
	}

	IMG_AddInstrumentFunction(ImageLoad, NULL);
	INS_AddInstrumentFunction(instrument_insn, NULL);
	TRACE_AddInstrumentFunction(instrument_trace, NULL);
	
	PIN_AddSyscallEntryFunction(SyscallEntry, NULL);
	PIN_AddSyscallExitFunction(SyscallExit, NULL);

	PIN_StartProgram();
	return true;
}

void after_openat(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std) {
	char* file_name = (char*)PIN_GetSyscallArgument(ctxt, std, 1);
	LOG_INFO("syscall_openat:\tfilename:%s\n", file_name);
}
