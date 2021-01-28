#include <intrin.h>
#include <string>
#include <Windows.h>
#include "retcheck.h"

#define AddCallBack(a) 	AddVectoredExceptionHandler(1, a)

class UtilsClass {
public:
	DWORD FindPatternInMemory(unsigned char* pData, unsigned int end_addr, const unsigned char* pat, const char* msk)
	{
		const unsigned char* end = (unsigned char*)end_addr - strlen(msk);
		int num_masks = ceil((float)strlen(msk) / (float)16);
		int masks[32];
		memset(masks, 0, num_masks * sizeof(int));
		for (int i = 0; i < num_masks; ++i)
			for (int j = strnlen(msk + i * 16, 16) - 1; j >= 0; --j)
				if (msk[i * 16 + j] == 'x')
					masks[i] |= 1 << j;

		__m128i xmm1 = _mm_loadu_si128((const __m128i*) pat);
		__m128i xmm2, xmm3, mask;
		for (; pData != end; _mm_prefetch((const char*)(++pData + 64), _MM_HINT_NTA)) {
			if (pat[0] == pData[0]) {
				xmm2 = _mm_loadu_si128((const __m128i*) pData);
				mask = _mm_cmpeq_epi8(xmm1, xmm2);
				if ((_mm_movemask_epi8(mask) & masks[0]) == masks[0]) {
					for (int i = 1; i < num_masks; ++i) {
						xmm2 = _mm_loadu_si128((const __m128i*) (pData + i * 16));
						xmm3 = _mm_loadu_si128((const __m128i*) (pat + i * 16));
						mask = _mm_cmpeq_epi8(xmm2, xmm3);
						if ((_mm_movemask_epi8(mask) & masks[i]) == masks[i]) {
							if ((i + 1) == num_masks)
								return (DWORD)pData;
						}
						else goto cont;
					}
					return (DWORD)pData;
				}
			}cont:;
		}
		return NULL;
	}
};


UtilsClass RoboUtils;
uintptr_t CallCheckLocation;
typedef int(*BackHandle)(DWORD);


union r_Value {
	PVOID gc;
	PVOID p;
	double n;
	int b;
};


struct r_TValue {
	r_Value value;
	int tt;
};


#define UPVAL -10003
#define REBASE_ADDRESS(x) ((int)GetModuleHandle(NULL) + x - 0x400000)

#define DeclareX(address, returnValue, callingConvention, ...) (returnValue(callingConvention*)(__VA_ARGS__))(Retcheck::unprotect((BYTE*)(REBASE_ADDRESS(address))))
auto rindex2 = DeclareX(0x823ae0, r_TValue*, __stdcall, DWORD a1, int idx);
auto rpushlightuserdata = DeclareX(0x82de60, void, __cdecl, DWORD a1, void* p);
auto rpushcclosure = DeclareX(0x82DC00, void, __cdecl, DWORD a1, int a2, int a3);

int JMPBackHandler(DWORD rL) {
	BackHandle handle = (BackHandle)(rindex2(rL, UPVAL)->value.p);
	return handle(rL);
}
void pushcclosure_bypass(DWORD State, int* fn, DWORD n)
{
	rpushlightuserdata(State, fn);
	rpushcclosure(State, CallCheckLocation, n);
}

LONG WINAPI CallBackHandler(PEXCEPTION_POINTERS ex)
{
	switch (ex->ExceptionRecord->ExceptionCode)
	{
	case (DWORD)0x80000003L:
	{
		if (ex->ContextRecord->Eip == CallCheckLocation)
		{
			ex->ContextRecord->Eip = (DWORD)(JMPBackHandler);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		return -1;
	}
	default: return 0;
	}
	return 0;
}

class CallCheckClass {
public:
	bool InitBypasses() {
		DWORD Start = (DWORD)GetModuleHandle(NULL);
		DWORD Offset = Start + 0x1000;
		MEMORY_BASIC_INFORMATION MemoryInformation;
		CallCheckLocation = RoboUtils.FindPatternInMemory((unsigned char*)Offset, MemoryInformation.RegionSize + Offset, (unsigned char*)"\xCC\xCC\xCC\xCC", "xxxx");
		AddVectoredExceptionHandler(1, CallBackHandler);
		return true;
	}
};

CallCheckClass CallCheck;
