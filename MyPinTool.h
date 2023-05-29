#pragma once
#include <pin.H>

#include <stdio.h>

#include <string>
#include <map>
#include <vector>
#include <tuple>
#include <stack>
#include <memory>

#include <unistd.h>

#include <x86_64-linux-gnu/sys/syscall.h>
#include <x86_64-linux-gnu/asm/unistd_64.h>

#define ADDRINT unsigned long long 

//日志文件描述符
FILE* init_thread_stdout();
extern thread_local FILE* thread_new_stdout;

//输出日志宏
#define LOG_INFO(fmt,...) fprintf(thread_new_stdout,fmt,##__VA_ARGS__);

#ifdef DEBUG
#define DEBUG_INFO(fmt,...) fprintf(thread_new_stdout,"debug_info:\t"#fmt,##__VA_ARGS__); 
#else
#define DEBUG_INFO(fmt,...) 
#endif // DEBUG

/*
	符号解析
*/
//SymInfo 保存符号信息，地址范围和符号名
class SymInfo {
public:
	//std::tuple<ADDRINT:符号起始地址，ADDRINT:符号终止地址，std::shared_ptr<std::string>符号名>
	using SymInfoType = std::tuple<ADDRINT, ADDRINT, std::shared_ptr<std::string>>;

	void insert_syminfo(ADDRINT image, ADDRINT sym_b, ADDRINT sym_e, std::shared_ptr<std::string> sym_name);

	ADDRINT query_syminfo(ADDRINT image, ADDRINT ip, std::shared_ptr<std::string>& sym_name);

	ADDRINT query_syminfo(ADDRINT ip, std::shared_ptr<std::string>& sym_name);

private:
	std::map<ADDRINT, std::vector<SymInfoType>> sym_info;
};
extern SymInfo SymInfoMgr;

/*
内存读写监控
*/
 


/*
	函数调用监控(call)
*/
//保存call指令的上下文信息，call指令地址，目标跳转地址。用于call上下文回溯。
//由于存在递归调用的情况，所以在保存call的返回地址时使用的stack结构
//由于无法监控内核指令流和非主模块指令流(限制指令范围)会造成部分正常控制流没有起始指令地址，目标指令流的信息
class CallTraceInfo {
public:
	//std::tuple<ADDRINT:call指令地址, ADDRINT:call跳转地址, ADDRINT:可选参数，回调中使用>
	using CallTraceInfoType = std::tuple<ADDRINT, ADDRINT, ADDRINT>;

	void insert_callinfo(THREADID tid, ADDRINT src_ip, ADDRINT dst_ip, ADDRINT ret_dst);

	CallTraceInfoType query_callinfo(THREADID tid, ADDRINT ret_src, ADDRINT ret_dst);
	void pop_callinfo(THREADID tid, ADDRINT ret_src, ADDRINT ret_dst);
private:
	std::map<ADDRINT, std::map<ADDRINT, std::stack<CallTraceInfoType>>> call_trace_info;
};
extern CallTraceInfo CallTraceInfoMgr;

//分析call指令的分析函数，callAfter在call指令执行后调用，retBefor在ret指令执行后调用
static void callAfter(ADDRINT ip, ADDRINT dst, CONTEXT* ctxt, THREADID tid);
static void retBefor(ADDRINT ret_src, ADDRINT ret_dst, CONTEXT* ctxt, THREADID tid);

//call回调函数原型
using CALL_MONITOR_CALLBACK_BEFORE = void (*)(THREADID tid, ADDRINT call_src, ADDRINT call_dst, CONTEXT* ctxt);
using CALL_MONITOR_CALLBACK_AFTER = void (*)(THREADID tid, ADDRINT call_src, ADDRINT call_dst, ADDRINT ret_src, ADDRINT ret_dest, CONTEXT* ctxt);
extern std::map<ADDRINT, std::tuple<CALL_MONITOR_CALLBACK_BEFORE, CALL_MONITOR_CALLBACK_AFTER>> FuncCallMonitor;
#define CALL_CALLBLACK_ITEM(ip,before,after) {FuncCallMonitor[(ip)]=std::tuple<CALL_MONITOR_CALLBACK_BEFORE, CALL_MONITOR_CALLBACK_AFTER>((before),(after));}

//在函数中初始化call回调函数，在main函数中调用
void call_callback_init();

/*
	系统调用监控(syscall)
*/
//SyscallTraceInfo，保存系统调用上下文信息，一个线程在同一时间内只能执行一个系统调用。
class SyscallTraceInfo {
public:
	//std::tuple<ADDRINT:系统调用号,ADDRINT:系统调用的地址,ADDRINT:可选参数，用于回调函数>
	using SyscallTraceInfoType = std::tuple<ADDRINT,ADDRINT,ADDRINT>;
	void insert_syscall_info(THREADID tid, ADDRINT order, ADDRINT src, ADDRINT param);

	SyscallTraceInfoType& query_syscall_trace_info(THREADID tid);
private:
	std::map< THREADID, SyscallTraceInfoType> syscall_trace_info;
};
extern SyscallTraceInfo SyscallTraceInfoMgr;

//系统调用分析函数
void SyscallEntry(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, void* param);
void SyscallExit(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, void* param);

//在函数中初始化syscall回调函数，在main函数中调用
void syscall_callback_init();

//系统调用回调函数原型
using SYSCALL_MONITOR_CALLBACK_BEFORE = void(*)(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std);
using SYSCALL_MONITOR_CALLBACK_AFTER = void(*)(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std);
extern std::map<ADDRINT, std::tuple<SYSCALL_MONITOR_CALLBACK_BEFORE, SYSCALL_MONITOR_CALLBACK_AFTER>> SyscallCallMonitor;
#define SYSCALL_CALLBLACK_ITEM(order,before,after) {SyscallCallMonitor[(order)]=std::tuple<SYSCALL_MONITOR_CALLBACK_BEFORE, SYSCALL_MONITOR_CALLBACK_AFTER>((before),(after));}

/*
	系统调用回调函数
*/

#define PRINTF_SYSCALL_INFO(sysname,type1,name1,type2,value2)

void after_openat(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std);

/*
虚拟环境
*/
enum HandleType { FILE_OBJECT, SOCKET_OBJECT };

class HnadleObject {
public:
	HnadleObject(std::string name, HandleType type) : handle_desc(name), handle_type(type) {};
private:
	std::string handle_desc;
	HandleType handle_type;
};

class FileObject :HnadleObject {
public:
	FileObject(std::string path) : HnadleObject(path, HandleType::FILE_OBJECT) {};
	FileObject(FileObject tmp) {};
private:
	bool redirct;
};

class SocketObject :HnadleObject {
public:
	SocketObject(std::string _ip, ushort _port):ip(_ip),port(_port) {};

private:
	std::string ip;
	ushort port;
};

class VirtualEnvironment {
public:
	VirtualEnvironment() {};
	void insert_handle(int fd, std::shared_ptr<HnadleObject> object) {
		handle_table[fd] = object;
	}
	const std::shared_ptr<HnadleObject>& query_handle(int fd) {
		return handle_table[fd];
	}
private:
	std::map<int, std::shared_ptr<HnadleObject>> handle_table;
};


/*
	PinTool插桩函数
*/
//映像级插桩函数	监控模块加载，解析模块符号信息
static void ImageLoad(IMG img, void* param);
//踪迹级插桩函数	代码块信息记录
static void instrument_trace(TRACE trace, void* param);
//指令级插桩函数	监控函数调用(call,ret),监控内存读写
static void instrument_insn(INS ins, void* param);
//PinTool入口点
int main(int argc, char* argv[]);

