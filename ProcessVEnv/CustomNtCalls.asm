.CODE

; ----- suspend_me_main -----
suspend_me_main_STARTP::
suspend_me_main PROC
; RCX - entry_point_t, RDX - PPEB
	mov eax, 1BEh			; NtSuspendThread
	mov r11, rdx
	mov r10, -2 			; hThread
	mov rdx, 0				; PreviousSuspendCount
	syscall

; Should not get here. Cannot return in kernel
	ret
suspend_me_main ENDP
suspend_me_main_ENDP::
int 3



.DATA

PUBLIC suspend_me_main_START
suspend_me_main_START::
dq OFFSET suspend_me_main_STARTP

PUBLIC suspend_me_main_END
suspend_me_main_END::
dq OFFSET suspend_me_main_ENDP



END