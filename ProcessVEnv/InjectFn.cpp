#include "InjectFn.h"
#include "CustomNtCalls.h"

// you CANNOT run static dll calls

#pragma optimize( "", off )
#pragma runtime_checks("", off)

/* loader data segment */
#pragma data_seg(".ldd$a") // start byte
#pragma data_seg(".ldd$z") // end byte
#pragma data_seg(".ldd$u") // data
// no const because it's another segment. const_seg(".rdata")

/* loader code segment */
#pragma code_seg(".ld$a") // start byte
#pragma code_seg(".ld$z") // end byte
#pragma code_seg(".ld$u") // code

__declspec(allocate(".ldd$a")) const int ldd_section_START = 1;
__declspec(allocate(".ldd$z")) const int ldd_section_END = 1;

__declspec(allocate(".ld$a")) const int ld_section_START = 1;
__declspec(allocate(".ld$z")) const int ld_section_END = 1;

#pragma region LOADER GVARS
static ULONG ntdll_size = 0;
static HANDLE ntdll = INVALID_HANDLE_VALUE;

static BYTE sig_LdrGetProcedureAddressForCaller[] = {
	0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41,
	0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C,
	0x24, 0xE8, 0x48, 0x81, 0xEC, 0x18, 0x01, 0x00,
	0x00, 0x48, 0x8B, 0x05, 0x30, 0x47, 0x15, 0x00
};
typedef decltype(LdrGetProcedureAddressForCaller)* pLdrGetProcedureAddressForCaller_t;
static pLdrGetProcedureAddressForCaller_t pLdrGetProcedureAddressForCaller = nullptr;

static WCHAR ntdll_name[] = L"ntdll.dll";
static CHAR memcpy_name[] = "memcpy";
static CHAR NtProtectVirtualMemory_name[] = "NtProtectVirtualMemory";
static CHAR NtFreeVirtualMemory_name[] = "NtFreeVirtualMemory";
static CHAR NtAllocateVirtualMemory_name[] = "NtAllocateVirtualMemory";
static CHAR NtCreateFile_name[] = "NtCreateFile";
static CHAR NtSuspendThread_name[] = "NtSuspendThread";

/* in this struct hooker functions must be original */
struct NtdllProcedures {
	decltype(memcpy)* pmemcpy;
	decltype(NtProtectVirtualMemory)* pNtProtectVirtualMemory;
	decltype(NtFreeVirtualMemory)* pNtFreeVirtualMemory;
	decltype(NtAllocateVirtualMemory)* pNtAllocateVirtualMemory;
	decltype(NtCreateFile)* pNtCreateFile;
};
static NtdllProcedures ntdll_procs;
#pragma endregion

#pragma region STRING MANIPULATIONS
static DECLSPEC_NOINLINE void ld_init_ustr(OUT PUNICODE_STRING ustr, IN PWSTR str, IN USHORT size) {
	ustr->Buffer = str;
	ustr->MaximumLength = size * sizeof(WCHAR);
	ustr->Length = ustr->MaximumLength - sizeof(WCHAR);
}
template<USHORT _Size>
static inline void ld_init_custr(OUT PUNICODE_STRING ustr, IN const WCHAR(&str)[_Size]) {
	ld_init_ustr(ustr, const_cast<PWSTR>(str), _Size);
}
static DECLSPEC_NOINLINE void ld_init_astr(OUT PANSI_STRING astr, IN PSTR str, IN USHORT size) {
	astr->Buffer = str;
	astr->MaximumLength = size * sizeof(CHAR);
	astr->Length = astr->MaximumLength - sizeof(CHAR);
}
template<USHORT _Size>
static inline void ld_init_castr(OUT PANSI_STRING astr, IN const CHAR(&str)[_Size]) {
	ld_init_astr(astr, const_cast<PSTR>(str), _Size);
}
static DECLSPEC_NOINLINE int ld_ustrcmp(IN const PUNICODE_STRING ustr_a, IN const PUNICODE_STRING ustr_b) {
	if (ustr_a->Length != ustr_b->Length) {
		return ustr_a->Length - ustr_b->Length;
	}
	for (int i = 0; i < ustr_a->Length / sizeof(WCHAR); ++i) {
		if (ustr_a->Buffer[i] != ustr_b->Buffer[i]) {
			return ustr_a->Buffer[i] - ustr_b->Buffer[i];
		}
	}
	return 0;
}
#pragma endregion

#pragma region MEMORY MANIPULATIONS
/* change protection and return old protection. If error return PAGE_TARGETS_INVALID */
static DECLSPEC_NOINLINE ULONG ld_change_prot(IN PVOID address, IN SIZE_T size, IN ULONG new_prot) {
	NTSTATUS status;
	PVOID page_address = address;
	ULONG old_prot;
	status = ntdll_procs.pNtProtectVirtualMemory(CURRENT_PROCESS, &page_address, &size, new_prot, &old_prot);
	if (!NT_SUCCESS(status)) {
		return PAGE_TARGETS_INVALID;
	}
	return old_prot;
}
/* free memory returned by ld_calloc or ld_hook_syscall. */
static DECLSPEC_NOINLINE void ld_free(IN PVOID address) {
	NTSTATUS status;
	PVOID page_address = address;
	SIZE_T size = 0;
	auto pNtFreeVirtualMemory = reinterpret_cast<decltype(NtFreeVirtualMemory)*>(PROC_AT_OFFSET(ntdll, 0x9D390));
	status = pNtFreeVirtualMemory(CURRENT_PROCESS, &page_address, &size, MEM_RELEASE);
}
/* allocate memory and return memory address. Default allocate PAGE_READWRITE. Allocate size = count * sizeof(T). If error return nullptr */
template<typename T>
static DECLSPEC_NOINLINE T* ld_calloc(IN SIZE_T count, IN ULONG prot = PAGE_READWRITE) {
	NTSTATUS status;
	PVOID page_address = nullptr;
	ULONG zero_bits = 0;
	SIZE_T size = count * sizeof(T);
	SIZE_T alloc_size = size;
	auto pNtAllocateVirtualMemory = reinterpret_cast<decltype(NtAllocateVirtualMemory)*>(PROC_AT_OFFSET(ntdll, 0x9D2D0));
	status = pNtAllocateVirtualMemory(CURRENT_PROCESS, &page_address, zero_bits, &alloc_size, MEM_COMMIT, prot);
	if (!NT_SUCCESS(status)) {
		return nullptr;
	}
	if (alloc_size < size) {
		// Not enough memory?
		ld_free(page_address);
		return nullptr;
	}
	return reinterpret_cast<T*>(page_address);
}
/* Copy memory from src to dst. No overlap */
static DECLSPEC_NOINLINE void ld_memcpy(OUT PVOID dst, IN PVOID src, IN SIZE_T size) {
	ntdll_procs.pmemcpy(dst, src, size);

	//PBYTE dst_bytes = reinterpret_cast<PBYTE>(dst);
	//PBYTE src_bytes = reinterpret_cast<PBYTE>(src);
	//for (SIZE_T i = 0; i < size; ++i) {
	//	dst_bytes[i] = src_bytes[i];
	//}
}
static DECLSPEC_NOINLINE int ld_memcmp(IN PVOID buf1, IN PVOID buf2, IN SIZE_T size) {
	//auto pmemcmp = reinterpret_cast<decltype(memcmp)*>(PROC_AT_OFFSET(ntdll, 0x936A0));
	//return pmemcmp(buf1, buf2, size);

	PBYTE buf1_bytes = reinterpret_cast<PBYTE>(buf1);
	PBYTE buf2_bytes = reinterpret_cast<PBYTE>(buf2);
	for (SIZE_T i = 0; i < size; ++i) {
		if (buf1_bytes[i] != buf2_bytes[i]) {
			return buf1_bytes[i] - buf2_bytes[i];
		}
	}
	return 0;
}
static DECLSPEC_NOINLINE PVOID ld_memmem(IN PVOID haystack, IN SIZE_T haystack_len, IN PVOID needle, IN SIZE_T needle_len)
{
	if (haystack == nullptr) return nullptr;
	if (haystack_len == 0) return nullptr;
	if (needle == nullptr) return nullptr;
	if (needle_len == 0) return nullptr;

	for (PBYTE h = reinterpret_cast<PBYTE>(haystack); haystack_len >= needle_len; ++h, --haystack_len) {
		if (ld_memcmp(h, needle, needle_len) == 0) {
			return h;
		}
	}
	return nullptr;
}
#pragma endregion

#pragma region INIT FUNCTIONS
/* Get ntdll.dll HANDLE from PEB_LDR_DATA, also return ntdll.dll image size. If not found return INVALID_HANDLE_VALUE */
static DECLSPEC_NOINLINE HANDLE ld_get_ntdll(IN PPEB peb, OUT PULONG image_size) {
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLIST_ENTRY ldr_list_start = &ldr->InLoadOrderModuleList;
	PLIST_ENTRY ldr_list_node = ldr_list_start->Flink;
	UNICODE_STRING ntdll_name_ustr;
	ld_init_custr(&ntdll_name_ustr, ntdll_name);
	while (ldr_list_node != ldr_list_start) {
		PLDR_DATA_TABLE_ENTRY ldr_data = container_of(ldr_list_node, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (ld_ustrcmp(&ldr_data->BaseDllName, &ntdll_name_ustr) == 0) {
			*image_size = ldr_data->SizeOfImage;
			return ldr_data->DllBase;
		}
		ldr_list_node = ldr_data->InLoadOrderLinks.Flink;
	}
	return INVALID_HANDLE_VALUE;
}

/* find function with given signature and return it. If not found return nullptr */
template<typename T>
static DECLSPEC_NOINLINE T ld_ntdll_patchfind(IN PBYTE signature, IN ULONG size) {
	return reinterpret_cast<T>(ld_memmem(ntdll, ntdll_size, signature, size));
}
/* get procedure address with name. If not found return nullptr */
static inline PVOID ld_ntdll_get_proc_address(IN const PSTR name, IN USHORT size) {
	PVOID callback = nullptr;
	PVOID proc;
	NTSTATUS status;
	ANSI_STRING name_astr;
	ld_init_astr(&name_astr, name, size);
	status = pLdrGetProcedureAddressForCaller(ntdll, &name_astr, 0, &proc, 0, &callback);
	if (!NT_SUCCESS(status)) {
		return nullptr;
	}
	return proc;
}
template<typename T, USHORT _Size>
static inline T ld_ntdll_get_proc_address(IN const CHAR(&name)[_Size]) {
	return reinterpret_cast<T>(ld_ntdll_get_proc_address(const_cast<PSTR>(name), _Size));
}

/* init pLdrGetProcedureAddressForCaller and all pointers in ntdll_procs. If error return -1, otherwise 0 */
static DECLSPEC_NOINLINE int ld_init_ntdll_procs() {
	pLdrGetProcedureAddressForCaller = ld_ntdll_patchfind<pLdrGetProcedureAddressForCaller_t>(
		sig_LdrGetProcedureAddressForCaller,
		sizeof(sig_LdrGetProcedureAddressForCaller)
	);
	if (pLdrGetProcedureAddressForCaller == nullptr) {
		// failed to get LdrGetProcedureAddressForCaller from ntdll
		return -1;
	}

	ntdll_procs.pmemcpy = ld_ntdll_get_proc_address<decltype(NtdllProcedures::pmemcpy)>(memcpy_name);
	if (ntdll_procs.pmemcpy == nullptr) return -1;

	ntdll_procs.pNtAllocateVirtualMemory = ld_ntdll_get_proc_address<decltype(NtdllProcedures::pNtAllocateVirtualMemory)>(NtAllocateVirtualMemory_name);
	if (ntdll_procs.pNtAllocateVirtualMemory == nullptr) return -1;

	ntdll_procs.pNtFreeVirtualMemory = ld_ntdll_get_proc_address<decltype(NtdllProcedures::pNtFreeVirtualMemory)>(NtFreeVirtualMemory_name);
	if (ntdll_procs.pNtFreeVirtualMemory == nullptr) return -1;

	ntdll_procs.pNtProtectVirtualMemory = ld_ntdll_get_proc_address<decltype(NtdllProcedures::pNtProtectVirtualMemory)>(NtProtectVirtualMemory_name);
	if (ntdll_procs.pNtProtectVirtualMemory == nullptr) return -1;

	ntdll_procs.pNtCreateFile = ld_ntdll_get_proc_address<decltype(NtdllProcedures::pNtCreateFile)>(NtCreateFile_name);
	if (ntdll_procs.pNtCreateFile == nullptr) return -1;

	return 0;
}
#pragma endregion

/* Check for relative JMP at start of function. For example my antivirus already injects into NtCreateFile with relative JMP and break orig function pointer.
	Return nullptr if no JMP and return absolute pointer if it there */
static DECLSPEC_NOINLINE PVOID ld_check_for_reljmp(PVOID proc) {
	JMP_REL* try_jmp = reinterpret_cast<JMP_REL*>(proc);
	if (try_jmp->opcode[0] != 0xE9) {
		return nullptr;
	}
	return reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(proc) + try_jmp->rel_address + sizeof(JMP_REL));
}

static inline void ld_write_abs_jmp(PVOID proc, PVOID address) {
	struct {
		MOV_ABS_RAX mov_asm;
		JMP_ABS_RAX jmp_asm;
	} hook_opcodes;
	hook_opcodes.mov_asm.value = reinterpret_cast<uintptr_t>(address);
	ld_change_prot(proc, sizeof(hook_opcodes), PAGE_EXECUTE_READWRITE);
	ld_memcpy(proc, &hook_opcodes, sizeof(hook_opcodes));
	ld_change_prot(proc, sizeof(hook_opcodes), PAGE_EXECUTE_READ);
}

/* Hook syscall function. Return original function pointer allocated in memory. Deallocation required */
static DECLSPEC_NOINLINE PVOID ld_hook_syscall(PVOID proc, PVOID hook_proc) {
/* copy syscal function bytes. Original function */
	PBYTE orig_proc_bytes = ld_calloc<BYTE>(SYSCALL_PROC_SIZE);
	if (PVOID redirect_address = ld_check_for_reljmp(proc)) {
		// write jmp to hooker
		ld_write_abs_jmp(orig_proc_bytes, redirect_address);
	}
	else {
		// write original function
		ld_memcpy(orig_proc_bytes, reinterpret_cast<PBYTE>(proc), SYSCALL_PROC_SIZE);
		ld_change_prot(orig_proc_bytes, SYSCALL_PROC_SIZE, PAGE_EXECUTE_READ);
	}

/* write MOV and JMP absolute at start of function */
	
	ld_write_abs_jmp(proc, hook_proc);

	return orig_proc_bytes;
}
template<typename T>
static inline T ld_hook_syscall(PVOID proc, T hook_proc) {
	return reinterpret_cast<T>(ld_hook_syscall(proc, reinterpret_cast<PVOID>(hook_proc)));
}

static NTSTATUS NTAPI hooked_NtCreateFile(
	_Out_ PHANDLE file_handle,
	_In_ ACCESS_MASK access,
	_In_ POBJECT_ATTRIBUTES obj_attrs,
	_Out_ PIO_STATUS_BLOCK io_status,
	_In_opt_ PLARGE_INTEGER alloc_size,
	_In_ ULONG file_attrs,
	_In_ ULONG share_access,
	_In_ ULONG create_dispos,
	_In_ ULONG create_opts,
	_In_reads_bytes_opt_(ea_len) PVOID ea_buf,
	_In_ ULONG ea_len
) {
	//return ntdll_procs.pNtCreateFile(
	//	file_handle,
	//	access,
	//	obj_attrs,
	//	io_status,
	//	alloc_size,
	//	file_attrs,
	//	share_access,
	//	create_dispos,
	//	create_opts,
	//	ea_buf,
	//	ea_len
	//);
	return STATUS_ACCESS_DENIED;
}

/* main of loader */
static void loader_start(entry_point_t entry, PPEB peb) {
	ntdll = ld_get_ntdll(peb, &ntdll_size);
	if (ntdll == INVALID_HANDLE_VALUE) {
		// ntdll search failed
		return;
	}
	if (ld_init_ntdll_procs() < 0) {
		// failed to get all needed procedures
		return;
	}

	auto proc = ntdll_procs.pNtCreateFile;
	ntdll_procs.pNtCreateFile = ld_hook_syscall(proc, hooked_NtCreateFile);

	ld_ntdll_get_proc_address<decltype(NtSuspendThread)*>(NtSuspendThread_name)(CURRENT_THREAD, nullptr);

	// call entry point
	entry(peb);
}

/* Not needed in loader code, use const */
const uintptr_t loader_section_START = reinterpret_cast<uintptr_t>(&ld_section_START);
const uintptr_t loader_section_END = reinterpret_cast<uintptr_t>(&ld_section_END);
const size_t loader_section_SIZE = loader_section_END - loader_section_START;

const uintptr_t loader_start_POINTER = reinterpret_cast<uintptr_t>(&loader_start);
const uintptr_t loader_start_OFFSET = loader_start_POINTER - loader_section_START;

const uintptr_t loader_data_section_START = reinterpret_cast<uintptr_t>(&ldd_section_START);
const uintptr_t loader_data_section_END = reinterpret_cast<uintptr_t>(&ldd_section_END);
const size_t loader_data_section_SIZE = loader_data_section_END - loader_data_section_START;

// offset from start of loader code section
const intptr_t loader_data_section_OFFSET = loader_data_section_START - loader_section_START;

#pragma runtime_checks("", restore)
#pragma optimize("", on)