#pragma once
#include "../StubNtdll/ntdll.h"

extern "C" void __fastcall suspend_me_main(...);
extern "C" uint64_t suspend_me_main_START;
extern "C" uint64_t suspend_me_main_END;

const uint64_t suspend_me_main_SIZE = suspend_me_main_END - suspend_me_main_START;