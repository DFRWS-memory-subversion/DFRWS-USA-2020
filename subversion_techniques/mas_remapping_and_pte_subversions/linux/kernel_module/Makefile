ccflags-y := -std=gnu99 -Wno-declaration-after-statement -fno-optimize-sibling-calls
obj-m += rootkit_evil.o

rootkit_evil-objs := rootkit_module.o pte_modify.o pte_helper.o vma_modify.o helper.o debug.o pte_vma_delete.o

all:
	sudo make -C /lib/modules/`uname -r`/build M=$(PWD)

clean:
	sudo make -C /lib/modules/`uname -r`/build M=$(PWD) clean