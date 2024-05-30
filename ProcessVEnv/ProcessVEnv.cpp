// ProcessVEnv.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <cassert>
#include <intrin.h>

#include "CustomNtCalls.h"
#include "InjectFn.h"

#pragma comment(lib, "ntdll.lib")

int main(int argc, char** argv)
{
    //typedef void(*lds_t)(entry_point_t entry, PPEB peb);
    //((lds_t)loader_start_POINTER)(nullptr, NtCurrentPeb());
    //CreateFileA("hello.txt", GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL);

    NTSTATUS status;
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, const_cast<char*>("HelloWorldMsg.exe"), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

/* Write loader code */
    PVOID seg_address = nullptr;
    PVOID seg_change_address;
    SIZE_T seg_size = (loader_data_section_OFFSET + loader_data_section_SIZE);
    SIZE_T seg_change_size;
    SIZE_T written;
    ULONG old_prot;
    // allocate all loader segments
    status = NtAllocateVirtualMemory(pi.hProcess, &seg_address, 0, &seg_size, MEM_COMMIT, PAGE_READWRITE);
    // write loader code segment
    status = NtWriteVirtualMemory(
        pi.hProcess,
        seg_address,
        reinterpret_cast<void*>(loader_section_START),
        loader_section_SIZE,
        &written
    );
    // write loader data segment
    status = NtWriteVirtualMemory(
        pi.hProcess,
        reinterpret_cast<PBYTE>(seg_address) + loader_data_section_OFFSET,
        reinterpret_cast<void*>(loader_data_section_START),
        loader_data_section_SIZE,
        &written
    );
    // change loader code protection
    seg_change_address = seg_address;
    seg_change_size = loader_section_SIZE;
    status = NtProtectVirtualMemory(pi.hProcess, &seg_change_address, &seg_change_size, PAGE_EXECUTE_READ, &old_prot);
    
/* Apply loader to thread and save context */
    CONTEXT thread_ctx = { 0 };
    thread_ctx.ContextFlags = CONTEXT_FULL;
    NtGetContextThread(pi.hThread, &thread_ctx);
    //thread_ctx.Rcx = thread_ctx.Rip;
    thread_ctx.Rip = reinterpret_cast<uintptr_t>(seg_address) + loader_start_OFFSET;
    NtSetContextThread(pi.hThread, &thread_ctx);

    NtResumeThread(pi.hThread, nullptr);

    uint64_t address = 0;
    status = NtQueryInformationThread(pi.hThread, ThreadQuerySetWin32StartAddress, &address, sizeof(uint64_t), NULL);

    PROCESS_BASIC_INFORMATION proc_info;
    status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &proc_info, sizeof(proc_info), nullptr);

    THREAD_BASIC_INFORMATION thread_info;
    status = NtQueryInformationThread(pi.hThread, ThreadBasicInformation, &thread_info, sizeof(thread_info), NULL);

    PEB proc_peb;
    SIZE_T readed;

    status = NtReadVirtualMemory(pi.hProcess, proc_info.PebBaseAddress, &proc_peb, sizeof(proc_peb), &readed);

    NtTerminateProcess(pi.hProcess, 0);

    std::cout << "Hello World!\n";
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
