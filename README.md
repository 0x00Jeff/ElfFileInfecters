## this is just a dev branch of the 64 bit version of the infector, if you came here to use this tool, you should get it from the [master branch](https://github.com/0x00Jeff/ElfFileInfecters)

# infect.s

a basic x86 elf file infector written in pure x86 assembly, using the Segment padding infection thechnique along with finding in-segment null-byte blocks

## assembling commands

first you want to `. asmrc` or append the content of that file to your `~/.bashrc` or `~/.zshrc` or whatever file your shell uses

then build the infector executable using

```
asm infect.s
```

and the payload file using

```
asm elf.s
```

## requirements

there are 2 requirements for the payload, to be postion independent, and to contain a DWORD value of 0x69696969 inside of it, or else the infection won't happen

now the payload doesn't have to be null-byte-free but that's preferable as it helps to generate a smaller code, refer to elf.s to get an idea of what an accepted payload should look like

## quick demo
note : the payload segfaults because it's trying to return to `0x69696969` which is not a valid address

![](demo.gif)

## todo list

- document the undocumented routines
- rename elf.s to payload.s and apply the change to the readme file and the gif
- make a better demo.gif
- <del>optimize</del> keep optimizing the original infecter 
- write a 64 version
- figure out a way to make it support both 32 and 64 elf files without writing every routine twice
- make it position indepedent then get rid of the null bytes (probably won't do this one)

any contribution would be much appreciated, tho it's preferable to be either an optimization of the already existed code or some theory that might help me add new features

## a special thanks

to pico (0x00pf) for his [original write up](https://0x00sec.org/t/elfun-file-injector/410) on elf file infection
