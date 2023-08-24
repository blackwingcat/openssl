#pragma once
#ifndef COMMONFIX
#define COMMONFIX
/************************************************************************
*                                                                       *
*   commonfix.h v 3.00-- This module is supported Windows 95/98/Me/2000 *
*                                           on VC++2005/2008/2010       *
*                                                                       *
*   Copyright (c) 2023, BlackWingCat/PFW . All rights reserved.         *
*                                                                       *
*   Blog: http://blog.livedoor.jp/blackwingcat/  Twitter:BlackWingCat   *
*  Usage:                                                               *
*#define WINVER2 0x0400 // or 0x0410 or 0x0500                          *
*#define DLLMODE        // DLL                                          *
*#include "commonfix.h"                                                 *
*  Add Link Option /FILEALIGN:4096 /MT or /MTd                          *
* if you want run Win9x with VC2008/VC2010                              *
*  use fcwin enabled execute flag after link                            *
************************************************************************/
#include <windows.h>
#include <windows.h>


#define 	PF_SSE3_INSTRUCTIONS_AVAILABLE   13
#define 	PF_COMPARE_EXCHANGE128   14
#define 	PF_XSAVE_ENABLED   17

#ifdef __cplusplus 
extern "C"{
#endif
#ifdef _SELFENT
#ifdef _CONSOLE
#pragma comment(linker,"/entry:mainCRTStartup2") 
#else
#pragma comment(linker,"/entry:WinMainCRTStartup2") 
//#pragma comment(lib, "shlwapi.lib")
#endif
#endif


#if (WINVER2 <= 0x0400)
 #ifdef _CONSOLE
 #pragma comment(linker,"/CONSOLE:Windows,4.00") 
 #else
 #pragma comment(linker,"/SUBSYSTEM:Windows,4.00") 
 #endif
#else
	#if (WINVER2 <= 0x0410)
	 #ifdef _CONSOLE
		#pragma comment(linker,"/CONSOLE:Windows,4.10") 
	 #else
		#pragma comment(linker,"/SUBSYSTEM:Windows,4.10") 
	 #endif
	#else
	 #ifdef _CONSOLE
		#pragma comment(linker,"/CONSOLE:Windows,5.00") 
	 #else
		#pragma comment(linker,"/SUBSYSTEM:Windows,5.00") 
	 #endif
	#endif
#endif

//#ifdef AAAAAAAA

const char strKERNEL32DLL[]="KERNEL32.DLL";
#if (WINVER2 <= 0x0400)//WIN95
#if _MSC_VER >=1400 //VC2005
const char strIsDebuggerPresent[]="IsDebuggerPresent";
BOOL _declspec(naked ) WINAPI IsDebuggerPresent_stub(void)
{
	_asm{
		push offset strKERNEL32DLL
		call DWORD PTR[GetModuleHandleA]
		and eax,eax
		jnz L1
		retn
L1:
		push offset strIsDebuggerPresent
		push eax		
		call DWORD PTR[GetProcAddress]
		and eax,eax
		jz L2
		call eax
L2:		retn
	}
}
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__IsDebuggerPresent(void){
	_asm{
		_emit 0xc3
		_emit 0xc3
		_emit 0xc3
		_emit 0xc3
	}
}
__declspec(naked) LONG WINAPI InterlockedCompareExchange_stub(
  LONG volatile* Destination,
  LONG Exchange,
  LONG Comperand) {
  __asm {
	mov ecx, [esp+4]
	mov edx, [esp+8]
	mov eax, [esp+0Ch]
	lock cmpxchg [ecx], edx
	retn 0xc
  }
}
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__InterlockedCompareExchange(DWORD flg1,DWORD flg2,DWORD flg3)
{
	_asm{
		_emit 0x60
		_emit 0x90
		_emit 0xc3
		_emit 0xc3
	}
}
BOOL WINAPI GetFileAttributesExW_stub(									
  wchar_t *Destination,int fInfoLevelId,WIN32_FILE_ATTRIBUTE_DATA *Exchange) {
	  HANDLE hF;
	  if(Exchange==NULL) {
		  return 0;
	  }	  

	  memset(Exchange, 0 ,sizeof(WIN32_FILE_ATTRIBUTE_DATA));
	  Exchange->dwFileAttributes=GetFileAttributesW(Destination);
	  hF=CreateFileW(Destination,GENERIC_READ ,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_EXISTING,0,0);
	  if(hF!=INVALID_HANDLE_VALUE) {
		  GetFileTime(hF,&Exchange->ftCreationTime,&Exchange->ftLastAccessTime,&Exchange->ftLastWriteTime);
		  Exchange->nFileSizeLow=GetFileSize(hF,&Exchange->nFileSizeHigh);
		  CloseHandle(hF);
		  return 1;
	  } else return 0;	  
}
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__GetFileAttributesExW(DWORD flg1,DWORD flg2,DWORD flg3)
{
	_asm{
		_emit 0x60
		_emit 0x90
		_emit 0xc3
		_emit 0x90
	}
}
#endif//VC2005
#if (_MSC_VER >=1600) ||  (_ATL_VER > 0x0700)

BOOL WINAPI IsProcessorFeaturePresent_stub(DWORD flg1){
	typedef BOOL (WINAPI *IPFP )(DWORD flg1);
//	IPFP PIPFP=NULL;
//	HINSTANCE hDll;
//	hDll=GetModuleHandleA(strKERNEL32DLL);
///	if(hDll){
//		PIPFP=(IPFP)GetProcAddress(hDll,"IsProcessorFeaturePresent");
//	}
//	if(PIPFP==NULL)
	{
		int FP=0;
#define ACPI_FLAG 0x400000
	_asm{
		xor eax,eax
		cpuid
		cmp eax,0x756e6547
		jnz L1
		mov eax,1
		cpuid
		and ah,0xf
		cmp ah,5
		jnz L1
		and al,0xf0
		cmp al,0x20
		jz L2
		cmp al,0x70
		jnz L1
L2:			
		or FP,1<<PF_FLOATING_POINT_PRECISION_ERRATA
L1:
		test edx,1
		jnz NOFPU
		or FP,1<<PF_FLOATING_POINT_EMULATED
NOFPU:
		test edx,0x10
		jnz NORDTSC
		or FP,1<<PF_RDTSC_INSTRUCTION_AVAILABLE
NORDTSC	:
		test edx,0x800000
		jnz NOMMX
		or FP,1<<PF_MMX_INSTRUCTIONS_AVAILABLE
NOMMX:
		test edx,0x01000000
		jnz NOFXSR
		or FP,1<< PF_XSAVE_ENABLED
NOFXSR:
		test edx,0x02000000//SSE
		jnz NOSSE
		or FP,1<<PF_XMMI_INSTRUCTIONS_AVAILABLE
NOSSE:	test edx,0x04000000//SSE2
		jnz NOSSE2
		or FP,1<<PF_XMMI64_INSTRUCTIONS_AVAILABLE
NOSSE2:	test ecx,1
		jnz NOSSE3
		or FP,1<<PF_SSE3_INSTRUCTIONS_AVAILABLE
NOSSE3:	test ecx,1<<13
		jnz NOCMPXCHG16B
		or FP,1<<PF_COMPARE_EXCHANGE128
NOCMPXCHG16B:
		mov eax,0x80000000
		cpuid
		cmp eax,0x80000001
		jb NO3DNOW
		mov eax,0x80000001
		cpuid
		test edx,0x80000000
		jnz NO3DNOW
		or FP,1<<PF_3DNOW_INSTRUCTIONS_AVAILABLE
NO3DNOW:
			mov ecx,flg1
			mov eax,1
			shl eax,cl
			and FP,eax
		}
		if((GetVersion()&0xf)<5){
	//Windows 95 で SSE2 命令を実行すると落ちるので念のため
			FP&=~(1<<PF_SSE3_INSTRUCTIONS_AVAILABLE);
			FP&=~(1<<PF_XMMI64_INSTRUCTIONS_AVAILABLE);
			FP&=~(1<<PF_COMPARE_EXCHANGE128);
			FP&=~(1<<PF_XSAVE_ENABLED);
			if((GetVersion()&0xf0)==0){//win95
				FP&=~(1<<PF_XMMI_INSTRUCTIONS_AVAILABLE);
			}
		}
		return FP;
	}
//	return PIPFP(flg1);
}


int _declspec(naked ) WINAPI _imp__IsProcessorFeaturePresent(DWORD flg1)
{
	_asm{
		_emit 0xc3
		_emit 0x90
		_emit 0xc3
		_emit 0xc3
	}
}
#endif//VC++2010
#endif//WIN95

#if (WINVER2 <= 0x0500)//WIN2000
int __declspec(naked) WINAPI EncodePointer_stub( int flg1){
	_asm{
        call DWORD PTR[GetCurrentProcessId]
     	xor eax,0x12345678
		ror eax,4
		xor eax,[esp+4]
		ror eax,4
        retn 4
	}
}
int __declspec(naked) WINAPI DecodePointer_stub( int flg1){
  _asm{

        call DWORD PTR[GetCurrentProcessId]
		xor eax,0x12345678
		ror eax,8
		xor eax,DWORD PTR[esp+4]
        rol eax,4
        retn 4
  }
}
int WINAPI FindActCtxSectionStringA_stub( int flg1,
					int flg2,
					int flg3,
					char *pszFilename,
					void *data)
{
	typedef int (WINAPI *FACSS)(int, int,int,char*,void*);
	FACSS FACSSA;
	HINSTANCE hDll;
	hDll=GetModuleHandleA(strKERNEL32DLL);
	if(hDll){
		FACSSA=(FACSS)GetProcAddress(hDll,"FindActCtxSectionStringA");
		if(FACSSA){
			return FACSSA(flg1,flg2,flg3,pszFilename,data);
		}
	}
	return 0;
}
int WINAPI FindActCtxSectionStringW_stub( int flg1,
					int flg2,
					int flg3,
					wchar_t *pszFilename,
					void *data)
{
	typedef int (WINAPI *FACSS )(int, int,int,wchar_t*,void*);
	FACSS FACSSW;
	HINSTANCE hDll;
	hDll=GetModuleHandleA(strKERNEL32DLL);
	if(hDll){
		FACSSW=(FACSS)GetProcAddress(hDll,"FindActCtxSectionStringW");
		if(FACSSW){
			return FACSSW(flg1,flg2,flg3,pszFilename,data);
		}
	}
	return 0;
}

#if (WINVER2 < 0x0500)//WINME
#if _MSC_VER >=1500 //VC2008

typedef BOOL (WINAPI *ICSAC)(HANDLE flg1,int flg2);
BOOL WINAPI InitializeCriticalSectionAndSpinCount_stub(HANDLE flg1,DWORD flg2){
	ICSAC PICSAC=NULL;
	HINSTANCE hDll;
	hDll=GetModuleHandleA(strKERNEL32DLL);
	if(hDll){
		PICSAC=(ICSAC)GetProcAddress(hDll,"InitializeCriticalSectionAndSpinCount");
	}
	if((GetVersion()&0xf)<5 || PICSAC==NULL){
		InitializeCriticalSection((LPCRITICAL_SECTION)flg1);
		return 1;
	}
	return PICSAC(flg1,flg2);
}
typedef BOOL (WINAPI *HSIS )(HANDLE flg1,int flg2,void *flg3,DWORD flg4);
BOOL WINAPI HeapSetInformation_stub(HANDLE flg1,int flg2,void *flg3,DWORD flg4){
	HSIS PHSIS;
	HINSTANCE hDll;
	hDll=GetModuleHandleA(strKERNEL32DLL);
	if(hDll){
		PHSIS=(HSIS)GetProcAddress(hDll,"HeapSetInformation");
		if(PHSIS){
			return PHSIS(flg1,flg2,flg3,flg4);
		}
	}
	return 0;

}
typedef BOOL (WINAPI *HQIS )(HANDLE flg1,int flg2,void*flg3,DWORD flg4,DWORD *flg5);
BOOL WINAPI HeapQueryInformation_stub(HANDLE flg1,int flg2,void*flg3,DWORD flg4,DWORD *flg5){
	HQIS PHQIS;
	HINSTANCE hDll;
	hDll=GetModuleHandleA(strKERNEL32DLL);
	if(hDll){
		PHQIS=(HQIS)GetProcAddress(hDll,"HeapQueryInformation");
		if(PHQIS){
			return PHQIS(flg1,flg2,flg3,flg4,flg5);
		}
	}
	return 0;
}

_declspec(dllexport)int _declspec(naked ) WINAPI _imp__InitializeCriticalSectionAndSpinCount( void* flg1,
					DWORD flg2)
{
	_asm{
		_emit 0x90
		_emit 0x90
		_emit 0xc3
		_emit 0x90
	}
}
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__HeapSetInformation( HANDLE flg1,int flg2,void *flg3,DWORD flg4)
{
	_asm{
		_emit 0x33
		_emit 0xc0
		_emit 0xc3
		_emit 0x90
	}
}
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__HeapQueryInformation( HANDLE flg1,int flg2,void*flg3,DWORD flg4,DWORD *flg5)
{
	_asm{
		_emit 0x33
		_emit 0xc0
		_emit 0x90
		_emit 0xc3
	}
}
#endif//VC2008
#endif//WINME

#if _MSC_VER >=1700 //VC2012
//
//  Windows 2000 XP API Wrapper Pack
//  Copyright (C) 2008 OldCigarette
VOID LoaderLock(BOOL lock) {
	PROCESS_BASIC_INFORMATION info;
	NTSTATUS status;
	status = NtQueryInformationProcess(
	    GetCurrentProcess(), ProcessBasicInformation, &info, sizeof(info), NULL);
		
	if(!NT_SUCCESS(status)) return;

	if(lock)
		RtlEnterCriticalSection(*(PRTL_CRITICAL_SECTION *)((PBYTE)info.PebBaseAddress + 0xA0));
	else
		RtlLeaveCriticalSection(*(PRTL_CRITICAL_SECTION *)((PBYTE)info.PebBaseAddress + 0xA0));
}

BOOL IncLoadCount(HMODULE hMod) {
	WCHAR buffer[MAX_PATH+1];
	DWORD nSize;
	nSize = GetModuleFileNameW(hMod, buffer, MAX_PATH+1);
	if(nSize <= MAX_PATH) {
		if(LoadLibraryW(buffer)) return TRUE;
		else                     return FALSE;
	}
	return FALSE;
}


BOOL WINAPI GetModuleHandleExW_stub(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule) {
	PROCESS_BASIC_INFORMATION info;
	PLDR_MODULE mod;
	PLDR_MODULE first_mod = NULL;
	BOOL inc_loadcount = FALSE;

	*phModule = NULL;
	LoaderLock(TRUE);
	if(dwFlags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) {
		NtQueryInformationProcess(
		    GetCurrentProcess(), ProcessBasicInformation, &info, sizeof(info), NULL);
		mod = (PLDR_MODULE)((PPEB_)info.PebBaseAddress)->LoaderData->InLoadOrderModuleList.Flink;
		while(mod != first_mod) {
			if((DWORD)mod->BaseAddress <= (DWORD)lpModuleName && 
			   (DWORD)lpModuleName < (DWORD)mod->BaseAddress + (DWORD)mod->SizeOfImage) {
				*phModule = mod->BaseAddress;
				break;
			}
			if(!first_mod) first_mod = mod;
			mod = (PLDR_MODULE)mod->InLoadOrderModuleList.Flink;
		}
	} else {
		*phModule = GetModuleHandleW(lpModuleName);
	}
	LoaderLock(FALSE);

	if(*phModule == NULL) return FALSE;
	*phModule = WrapGetModule(*phModule);

	LoaderLock(TRUE);
	mod = GetLdrModule(*phModule);
	if(!(dwFlags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT))
		inc_loadcount = TRUE;

	//How to pin? We'll just inc the LoadCount and hope
	if(dwFlags & GET_MODULE_HANDLE_EX_FLAG_PIN) 
		inc_loadcount = TRUE;
	LoaderLock(FALSE);
	
	if(inc_loadcount) {
		IncLoadCount(*phModule);
	}
	
	return TRUE;
}
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__GetModuleHandleEx()
{
	_asm{
		_emit 0x33
		_emit 0xc0
		_emit 0x66
		_emit 0xc3
	}
}

#endif

#if (_MSC_VER >=1600) ||  (_ATL_VER > 0x0700)
//VC2010
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__FindActCtxSectionStringA( int flg1,
					int flg2,
					int flg3,
					wchar_t *pszFilename,
					void *data)
{
	_asm{
		_emit 0x33
		_emit 0xc0
		_emit 0xc3
		_emit 0xc3
	}
}
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__FindActCtxSectionStringW( int flg1,
					int flg2,
					int flg3,
					wchar_t *pszFilename,
					void *data)
{
	_asm{
		_emit 0xc3
		_emit 0x33
		_emit 0xc0
		_emit 0xc3
	}
}
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__EncodePointer( int flg1)
{
	_asm{
		_emit 0xc3
		_emit 0xc3
		_emit 0x33
		_emit 0xc0
	}
}
_declspec(dllexport)int _declspec(naked ) WINAPI _imp__DecodePointer( int flg1)
{
	_asm{
		_emit 0x33
		_emit 0xc0
		_emit 0x33
		_emit 0xc0
	}
}
#endif//VC2010
#endif//Win2000
extern int __sse2_available;
int WINAPI get_sse2_info_stub(){
	__sse2_available =  0 ;
	return 0;
}
//extern _get_sse2_info
extern int __use_sse2_mathfcns;
//_declspec(dllexport)
int _get_sse2_info();
void initialize_findacx
(){
//	LoadLibraryA("unicows.lib");
	FARPROC i,x;
	DWORD dw;
	HINSTANCE hDll;
	if((GetVersion()&0xff)==4&&(GetVersion()&0xff00)==0)
	{
		i=(FARPROC)&_get_sse2_info;
	    VirtualProtect(i, sizeof(FARPROC), PAGE_EXECUTE_READWRITE	, &dw);
		*(FARPROC*)i=(FARPROC)0x90c3c033;//xor eax,eax ret
		VirtualProtect(i, sizeof(FARPROC), dw, &dw);
	}
	hDll=GetModuleHandleA(strKERNEL32DLL);
#if (WINVER2 <= 0x0400) //Win95
#if _MSC_VER >=1400 //VC2005
	x=GetProcAddress(hDll,"IsDebuggerPresent");

	if(x==0)x=(FARPROC)&IsDebuggerPresent_stub;
	i=(FARPROC)&_imp__IsDebuggerPresent;
	VirtualProtect(i, sizeof(FARPROC), PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);

	x=GetProcAddress(hDll,"InterlockedCompareExchange");
	if(x==0)x=(FARPROC)&InterlockedCompareExchange_stub;

	i=(FARPROC)&_imp__InterlockedCompareExchange;
	VirtualProtect(i, sizeof(FARPROC), PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);

	x=GetProcAddress(hDll,"GetFileAttributesExW");
	if(x==0)x=(FARPROC)&GetFileAttributesExW_stub;

	i=(FARPROC)&_imp__GetFileAttributesExW;
	VirtualProtect(i, sizeof(FARPROC), PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);

	
#if (_MSC_VER >=1600) ||  (_ATL_VER > 0x0700)
	x=GetProcAddress(hDll,"IsProcessorFeaturePresent");
	if(x==0)x=(FARPROC)&IsProcessorFeaturePresent_stub;

	i=(FARPROC)&_imp__IsProcessorFeaturePresent;
	VirtualProtect(i, sizeof(FARPROC), PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);


#endif//VC2010
#endif//VC2005
#endif//Win95

#if _MSC_VER >=1700 //VC2010
	x=GetProcAddress(hDll,"GetModuleHandleExW");
	if(x==0)x=(FARPROC)&GetModuleHandleExW_stub;

	i=(FARPROC)& _imp__GetModuleHandleExW;
    VirtualProtect(i, sizeof(FARPROC), PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);
#endif
#if (_MSC_VER >=1600) ||  (_ATL_VER > 0x0700)
	x=GetProcAddress(hDll,"FindActCtxSectionStringW");
	if(x==0)x=(FARPROC)&FindActCtxSectionStringW_stub;

	i=(FARPROC)& _imp__FindActCtxSectionStringW;
    VirtualProtect(i, sizeof(FARPROC), PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);

	x=GetProcAddress(hDll,"FindActCtxSectionStringA");
	if(x==0)x=(FARPROC)&FindActCtxSectionStringA_stub;

	i=(FARPROC)&_imp__FindActCtxSectionStringA;
    VirtualProtect(i, sizeof(FARPROC), PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);

	x=GetProcAddress(hDll,"EncodePointer");
	if(x==0)x=(FARPROC)&EncodePointer_stub;

	i=(FARPROC)&_imp__EncodePointer;
    VirtualProtect(i, sizeof(FARPROC), PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);

	x=GetProcAddress(hDll,"DecodePointer");
	if(x==0)x=(FARPROC)&DecodePointer_stub;

	i=(FARPROC)&_imp__DecodePointer;
    VirtualProtect(i, sizeof(FARPROC),PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);
#endif //VC2010
#if _MSC_VER >=1500 //VC2008
#if (WINVER2 < 0x0500) //WinMe
	x=GetProcAddress(hDll,"HeapQueryInformation");
	if(x==0)x=(FARPROC)&HeapQueryInformation_stub;

	i=(FARPROC)&_imp__HeapQueryInformation;
    VirtualProtect(i, sizeof(FARPROC),PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);

	x=GetProcAddress(hDll,"HeapSetInformation");
	if(x==0)x=(FARPROC)&HeapSetInformation_stub;

	i=(FARPROC)&_imp__HeapSetInformation;
    VirtualProtect(i, sizeof(FARPROC),PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);

	x=GetProcAddress(hDll,"InitializeCriticalSectionAndSpinCount");
	if(x==0)x=(FARPROC)&InitializeCriticalSectionAndSpinCount_stub;

	i=(FARPROC)&_imp__InitializeCriticalSectionAndSpinCount;
    VirtualProtect(i, sizeof(FARPROC),PAGE_EXECUTE_READWRITE	, &dw);
	*(FARPROC*)i=x;
	VirtualProtect(i, sizeof(FARPROC), dw, &dw);
#endif//Me
#endif//VC2008
}

#ifdef _SELFENT
 #ifdef DLLMODE
int WINAPI _DllMainCRTStartup(int hm,int rs,void *rev);
int WINAPI WinMainCRTStartup2(int hm,int rs,void *rev)
{
	if(rs==DLL_PROCESS_ATTACH)
		initialize_findacx();
	return _DllMainCRTStartup(hm,rs,rev);

}
 #else
 #ifdef _CONSOLE
extern void wmainCRTStartup();
extern void mainCRTStartup();
void mainCRTStartup2()
{
	initialize_findacx();
 #ifdef _UNICODE
	wmainCRTStartup();
 #else
	mainCRTStartup();
 #endif
}
 #else //CONSOLE
extern void wWinMainCRTStartup();
extern void WinMainCRTStartup();
void WinMainCRTStartup2()
{
	initialize_findacx();
#ifdef _UNICODE
	wWinMainCRTStartup();
#else
	WinMainCRTStartup();
#endif
}
#endif

#endif //DLLMODE
#endif //_SELFENT

//#endif //test


#ifdef __cplusplus 
}
#endif

#endif