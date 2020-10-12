# ElfFIleInfection
a collection of elf file infectors 

* infect.s
a basic x86 elf file infector in pure x86 assembly which can be assembled with the following command
`nasm -f elf infect.s -o infect.o &&  ld -m elf_i386 infect.o -o infect && rm infect.o`

there is only requirement, the payload should contains a DWORD value of 0x69696969 inside of it, or else the infection won't happen, this is because the executable needs a known value that can be replaced with the original pivot file's entry point, so we can continue executing the pivot file normally after executing the injected payload

refer to payload1.s and payload2.s to get an idea of what an accepted payload should look like
* ?
should be here soon

specially thanks to pico (0x00pf) who caused the motivation for making this
