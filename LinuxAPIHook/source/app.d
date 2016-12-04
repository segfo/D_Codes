import core.stdc.stdio;
import core.sys.linux.unistd;

// 常に100を返すrand
extern (C) int rand()
{
    return 100;
}

enum PtraceRequest{
	PTRACE_TRACEME
}
// 常に0を返すptrace(Anti-Anti-Debugging)
extern (C) long ptrace(int traceRequest,int pid,void* addr,void *data){
	switch(traceRequest){
		case	PtraceRequest.PTRACE_TRACEME:
			return 0;
		default:
			break;
	}
	return 0;
}

// constructor
shared static this()
{
}

// destructor
shared static ~this()
{
}
