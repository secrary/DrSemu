#pragma once

#include "includes.h"
#include "drwrap.h"
#include <combaseapi.h>

namespace dr_semu::com::handlers
{
	/*
	* The \p pre_func_cb can examine(drwrap_get_arg()) and set
	* (drwrap_set_arg()) the arguments to \p original and can skip the
	* call to \p original(drwrap_skip_call()).The \p post_func_cb can
	* examine(drwrap_get_retval()) and set(drwrap_set_retval()) \p
	* original's return value.  The opaque pointer \p wrapcxt passed to
	* each callback should be passed to these routines.
	*/

	// TODO (lasha): on reg key access check inproc
	// Pavels comment on TW

	inline void pre_co_create_instance(void* wrapcxt, void** user_data)
	{
		//HRESULT CoCreateInstance(
		//	_In_     REFCLSID rclsid,
		//	_In_opt_ LPUNKNOWN pUnkOuter,
		//	_In_     DWORD dwClsContext,
		//	_In_     REFIID riid,
		//	_COM_Outptr_ LPVOID FAR * ppv)

		constexpr auto args_size = sizeof(REFCLSID) + sizeof(LPUNKNOWN) + sizeof(DWORD) + sizeof(REFIID) + sizeof(PVOID
			);

		auto context = reinterpret_cast<DWORD>(drwrap_get_arg(wrapcxt, 2));

		//dr_printf("xCTX (before): 0x%lx\n", context);

		context = context & ~CLSCTX_REMOTE_SERVER; // unset
		drwrap_set_arg(wrapcxt, 2, reinterpret_cast<PVOID>(context));

		//dr_printf("xCTX (after): 0x%lx\n", context);
	}

	inline void pre_co_create_instance_ex(void* wrapcxt, void** user_data)
	{
		//HRESULT CoCreateInstanceEx(
		//	REFCLSID     Clsid,
		//	IUnknown * punkOuter,
		//	DWORD        dwClsCtx,
		//	COSERVERINFO * pServerInfo,
		//	DWORD        dwCount,
		//	MULTI_QI * pResults
		//);

		constexpr auto args_size = sizeof(REFCLSID) + sizeof(PVOID) + sizeof(DWORD) + sizeof(PVOID) + sizeof(DWORD) +
			sizeof(PVOID);

		auto context = reinterpret_cast<DWORD>(drwrap_get_arg(wrapcxt, 2));

		//dr_printf("CTX (before): 0x%lx\n", context);

		context = context & ~CLSCTX_REMOTE_SERVER;
		drwrap_set_arg(wrapcxt, 2, reinterpret_cast<PVOID>(context));

		//dr_printf("CTX (after): 0x%lx\n", context);
	}

	inline void pre_get_class_object(void* wrapcxt, void** user_data)
	{
		//HRESULT
		//CoGetClassObject(
		//	_In_ REFCLSID rclsid,
		//	_In_ DWORD dwClsContext,
		//	_In_opt_ LPVOID pvReserved,
		//	_In_ REFIID riid,
		//	_Outptr_ LPVOID  FAR * ppv
		//);

		constexpr auto args_size = sizeof(REFCLSID) + sizeof(DWORD) + sizeof(LPVOID) + sizeof(REFIID) + sizeof(PVOID);

		auto context = reinterpret_cast<DWORD>(drwrap_get_arg(wrapcxt, 1));

		//dr_printf("getCTX (before): 0x%lx\n", context);

		context = context & ~CLSCTX_REMOTE_SERVER;
		drwrap_set_arg(wrapcxt, 1, reinterpret_cast<PVOID>(context));

		//dr_printf("getCTX (after): 0x%lx\n", context);
	}
} // namespace dr_semu::com::handlers
