# ElfFIleInfection
a collection of elf file infectors 

## infect.s

a basic x86 elf file infector written in pure x86 assembly

## assembling command

`nasm -f elf infect.s -o infect.o &&  ld -m elf_i386 infect.o -o infect && rm infect.o`

## requirements

there are 2 requirements for the payload, to be postion independent, and to contain a DWORD value of 0x69696969 inside of it, or else the infection won't happen, this is because the executable needs a known value that can be replaced with the original pivot file's entry point, so we can continue executing the pivot file normally after executing the injected payload

now the payload doesn't have to be null-byte-free but that's preferable as it helps to generate a smaller code

refer to payload.s to get an idea of what an accepted payload should look like

## quick demo

![](demo.gif)

## a special thanks

to pico (0x00pf) for his [original write up](https://0x00sec.org/t/elfun-file-injector/410) on elf file infection
