#pragma once
#pragma warning(disable: 28252 28253)
#include "ntdll.h"
#pragma warning(restore: 28252 28253)
#include <inttypes.h>
#include <stddef.h>

#define ignore(x) (static_cast < void > (x))
#define countof(a) (sizeof(a) / sizeof(a[0]))
#define container_of(address, type, field) (reinterpret_cast<type*>(				 \
                                                  reinterpret_cast<uint8_t*>(address) - \
                                                  offsetof(type, field)))

#define ADDRESS_DIFF(a, b) (reinterpret_cast<uintptr_t>(a) > reinterpret_cast<uintptr_t>(b) ?	  \
								reinterpret_cast<uintptr_t>(a) - reinterpret_cast<uintptr_t>(b) : \
								reinterpret_cast<uintptr_t>(b) - reinterpret_cast<uintptr_t>(a))
#define PROC_AT_OFFSET(base, offset) (reinterpret_cast<uintptr_t>(base) + offset)

#define CURRENT_PROCESS reinterpret_cast<HANDLE>(-1LL)
#define CURRENT_THREAD reinterpret_cast<HANDLE>(-2LL)

#define SYSCALL_PROC_SIZE 0x18

// disable aligment. Assembler instructions
#pragma pack(push, 1)
struct MOV_ABS_RAX {
	const BYTE opcode[2] = { 0x48, 0xB8 };
	ULONGLONG value;
};
struct JMP_ABS_RAX {
	const BYTE opcode[2] = { 0xFF, 0xE0 };
};
struct JMP_REL {
	const BYTE opcode[1] = { 0xE9 };
	LONG rel_address;
};
#pragma pack(pop)

typedef uint64_t (__fastcall* entry_point_t)(PPEB);

/* loader code section */
extern const uintptr_t loader_section_START;
extern const uintptr_t loader_section_END;
extern const size_t loader_section_SIZE;

extern const uintptr_t loader_start_POINTER;
extern const uintptr_t loader_start_OFFSET;

/* loader data section */
extern const uintptr_t loader_data_section_START ;
extern const uintptr_t loader_data_section_END;
extern const size_t loader_data_section_SIZE;

// offset from loader code section
extern const intptr_t loader_data_section_OFFSET;