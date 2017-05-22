/**
*
* @brief ���� DLL Ӧ�ó������ڵ�
* @description ��������ṩ��Ŀ�깦�ܵ��࣬���Ƕ����ṩ�ķ�����һ���ͬС��
* @author Hamwa
* @see [�����/����]
*/
#include "stdafx.h"
//#include "pch.h"
#include <windows.h>
#include <stdio.h>  
#include "detours.h"
#pragma comment(lib, "lib/detours.lib")

//���������Ϣ
void WINAPI OutputDebugStringEx(char* lpcFormatText, ...)
{
	char szBuffer[1024];

	va_list argptr;
	va_start(argptr, lpcFormatText);
	vsprintf_s(szBuffer, (const char *)lpcFormatText, argptr);
	va_end(argptr);

	OutputDebugStringA(szBuffer);
}

//����ȫ����Ϣ������ַ����
PVOID g_pOldLoadLibrary = NULL;
PVOID g_pOldCreateWindow = NULL;
PVOID g_pOldRegisterClass = NULL;

//���嶯̬���Ƴ���
const char * SI_FRAME_CLASS_NAME = "si_Frame";
const char * KERNEL_32_DLL_NAME = "Kernel32.dll";
const char * USER_32_DLL = "User32.dll";
const char * SCI_LEXER_DLL = "SciLexer.dll";
const char * SI_UTF8_DLL = "siutf8.dll";
const char * SI_HOOK_DLL = "sihook.dll";

//����Hook������
typedef HMODULE(WINAPI *pFuncLoadLibrary)(const char* lpLibFileName);
typedef ATOM(WINAPI* pFuncRegisterClass)(CONST WNDCLASSW *lpWndClass);

typedef HWND(WINAPI * PfuncCreateWindow)(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName,DWORD dwStyle, int X, int Y,
		int nWidth,int nHeight, HWND hWndParent,HMENU hMenu,HINSTANCE hInstance, LPVOID lpParam);

static bool g_bLoadedSiHookDll = false;
static bool g_bLoadedUtf8Dll = false;
static bool g_bLoadedSciLexerDll = false;
static bool g_bLoadedSiEditHookDll = false;
static bool g_bLoadedSiSwHookDll = false;
static WNDPROC g_old_si_sw_proc = NULL;

//ɱ�����ñ�DLL��Ӧ�ó���
BOOL SelfKillProcess()
{
	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
	if (hProcess == NULL)
		return FALSE;
	OutputDebugStringEx("I will kill myself[%d]", GetLastError());
	if (!TerminateProcess(hProcess, 0))
		return FALSE;
	return TRUE;
}

static LRESULT CALLBACK SiSwSubClass(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{

	switch (uMsg) {
	case WM_CLOSE:
	{
		SelfKillProcess();
	}
		break;
	default:
		break;
	}
	LRESULT lr = CallWindowProc(g_old_si_sw_proc, hWnd, uMsg, wParam, lParam);

	return lr;
}

HWND WINAPI  New_CreateWindow(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X,
					int Y, int nWidth,int nHeight, HWND hWndParent,HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) {
	//��ӡ����������������
	//OutputDebugStringEx("Register ClassName New [%s]WindowName[%s]", lpClassName, lpWindowName);
	HWND retHwnd = ((PfuncCreateWindow)g_pOldCreateWindow)(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	if (lpClassName != NULL && strcmp(lpClassName, SI_FRAME_CLASS_NAME) == 0) {
		if (!g_bLoadedSiHookDll) {
			if (LoadLibraryA(SI_HOOK_DLL) == NULL){
				OutputDebugStringEx("LoadLibraryA :%s Failed[%d]", SI_HOOK_DLL, GetLastError());
			}else{
				OutputDebugStringEx("LoadLibraryA :%s Success[%d]", SI_HOOK_DLL, GetLastError());
				g_bLoadedSiHookDll = true;
				
				g_old_si_sw_proc = (WNDPROC)GetWindowLong(retHwnd, GWL_WNDPROC);
				SetWindowLong(retHwnd, GWL_WNDPROC, (DWORD)SiSwSubClass);
			}
		}
	} else {
		//OutputDebugStringEx("return ret.");
	}

	return retHwnd;
}

ATOM WINAPI  NEW_RegisterClass(CONST WNDCLASSW *lpWndClass)
{
	if (!g_bLoadedUtf8Dll) {
		if (LoadLibraryA(SI_UTF8_DLL) == NULL){
			OutputDebugStringEx("LoadLibraryA :%s Failed[%d]", SI_UTF8_DLL, GetLastError());
		}else{
			OutputDebugStringEx("LoadLibraryA :%s Success[%d]", SI_UTF8_DLL, GetLastError());
			g_bLoadedUtf8Dll = true;
		}		
	}
	if (!g_bLoadedSciLexerDll) {
		if (LoadLibraryA(SCI_LEXER_DLL) == NULL){
			OutputDebugStringEx("LoadLibraryA :%s Failed[%d]", SCI_LEXER_DLL, GetLastError());
		} else{
			OutputDebugStringEx("LoadLibraryA :%s Success[%d]", SCI_LEXER_DLL, GetLastError());
			g_bLoadedSciLexerDll = true;
		}
	}
	
	return ((pFuncRegisterClass)g_pOldRegisterClass)(lpWndClass);
}

extern "C" _declspec(dllexport) BOOL APIENTRY SetHook()
{
	//DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	g_pOldRegisterClass = DetourFindFunction(USER_32_DLL, "RegisterClassA");
	if (g_pOldRegisterClass == NULL) {
		MessageBoxA(NULL, "[HookFunction]DetourFindFunction failed", "Error", NULL);
	}
	
	g_pOldCreateWindow = DetourFindFunction(USER_32_DLL, "CreateWindowExA");
	if (g_pOldRegisterClass == NULL) {
		MessageBoxA(NULL, "[HookFunction]DetourFindFunction failed", "Error", NULL);
	}

	//�������������
	DetourAttach(&g_pOldRegisterClass, NEW_RegisterClass);
	DetourAttach(&g_pOldCreateWindow, New_CreateWindow);
	LONG ret = DetourTransactionCommit();
	if (ret != NO_ERROR) {
		OutputDebugStringEx("Loader DropHook Success[%d]", GetLastError());
	}

	return (ret == NO_ERROR);
}

extern "C" _declspec(dllexport) BOOL APIENTRY DropHook()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&g_pOldRegisterClass, NEW_RegisterClass);
	DetourDetach(&g_pOldCreateWindow, New_CreateWindow);
	LONG ret = DetourTransactionCommit();
	if (ret != NO_ERROR) {
		OutputDebugStringEx("Loader DropHook Success[%d]", GetLastError());
	}

	return (ret == NO_ERROR);
}

static HMODULE s_hDll;

HMODULE WINAPI Detoured()
{
	return s_hDll;
}

extern "C" BOOL APIENTRY DllMain( HMODULE hModule,
								  DWORD  ul_reason_for_call,
								  LPVOID lpReserved )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		 s_hDll = hModule;
		 DisableThreadLibraryCalls(hModule);
		 SetHook();
		 break;

	case DLL_THREAD_ATTACH:
		 break;

	case DLL_THREAD_DETACH:
		 break;

	case DLL_PROCESS_DETACH:
		 DropHook();
		 FreeLibraryAndExitThread(hModule, 0);
		 break;
	}

	return TRUE;
}