AS 	= nasm
ASFLAGS	= -f elf32

LD	= ld
LDFLAGS	= -m elf_i386

INFECT	= infect
INF_OBJ	= $(INFECT).o

PAYLOAD	= elf
PAY_OBJ	= $(PAYLOAD).o

SHARED	= shared.s
VPATH	= include


all: $(INFECT) $(PAYLOAD)


$(INFECT): $(INF_OBJ)
	$(LD) $(LDFLAGS) $^ -o $@

$(PAYLOAD): $(PAY_OBJ)
	$(LD) $(LDFLAGS) $^ -o $@

$(MAIN_OBJ): $(SHARED)
$(PAY_OBJ):

.PHONY: clean
clean:
	rm -f -- *.o

.PHONY: fclean
fclean:
	rm -f -- *.o
	rm -f infect elf
