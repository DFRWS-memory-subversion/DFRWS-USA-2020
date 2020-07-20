# DFRWS-USA-2020

This is the online repository for the paper ["Hiding Process Memory via Anti-Forensic Techniques"](https://dfrws.org/presentation/hiding-process-memory-via-anti-forensic-techniques/) by Ralph Palutke, Frank Block, Patrick Reichenberger and Dominik Stripeika. It contains all material referenced in the paper.

## Rekall Framework

[rekall_framework](rekall_framework) contains the Rekall version used during the evaluation. It is based on Rekall's Commit [041d696](https://github.com/google/rekall/tree/041d6964d871bd3170e9c2890901d2ecd8cdea4d) but with our modifications: Commit [b1c7888](https://github.com/DFRWS-memory-subversion/DFRWS-USA-2020/commit/b1c7888eaf8d0e8db9309ba6127f4914739a28c3)

Those modifications are required in order for the detection approaches to work.

## Subversion techniques Proof of Concept Implementations

The MAS remapping and PTE subversion implementation has mainly been done by Patrick Reichenberger (for Linux) and Dominik Stripeika (for Windows): Commit [9239d82](https://github.com/DFRWS-memory-subversion/DFRWS-USA-2020/tree/9239d829fadcc1abd42922bb8d4898ead4956c0a)

But it was modified for the evaluation of this paper: Commit [2cdd26e](https://github.com/DFRWS-memory-subversion/DFRWS-USA-2020/commit/2cdd26e26c90b257bb9faae294de2cea2532508d) (it's the current state of the code).

## Rekall Plugins

The Rekall plugins for the shared memory subversion detection are in the folder [detection](detection). They depend on our modifications to the [Rekall framework](rekall_framework).

## Commands used for evaluation

### Windows

Most actions have been done within a GUI. Exception is searching for malicious data and creating process dumps within WinDbg:

    s -a 0 L?0x7fffffffffff "what.the.eyes"

    .dump /mfFhutipwdc c:\users\user\procdump_windbg_mfFhutipwdc_hidden.dmp
    .dump /ma c:\users\user\procudmp_windbg_ma_hidden.dmp
    .dump /f c:\users\user\procdump_windbg_f_hidden.dmp

    .dump /mfFhutipwdc c:\users\user\procdump_windbg_mfFhutipwdc_unhidden.dmp
    .dump /ma c:\users\user\procdump_windbg_ma_unhidden.dmp
    .dump /f c:\users\user\procdump_windbg_f_unhidden.dmp



### Linux

Checking MASs and handles:

    cat /proc/$(pidof norm-process)/maps
    ls -lah /proc/$(pidof norm-process)/fd/

Creating core dump:

    gcore -o gcore_coredump $(pidof norm-process)

Searching for malicious memory and creating core dump in gdb:

    find 0x7f6ca27aa000,+0x1000,'w','h','a','t','.','t','h','e','.','e','y','e','s'
    find 0x7f6ca27aa000,+0x2000,'T','h','e',' ','m','a','l','i','c','i','o','u','s',' ','a','c','t','i','o','n'

    generate-core-file

## Tools used for false positive evaluation

### Debian 9.9 4.9.0-11-amd64

| Tool                                      | Version |
|-------------------------------------------|---------|
| firefox-esr                               | 68.4.1esr-1~deb9u1 |
| chromium                                  | 73.0.3683.75-1~deb9u1 |
| libreoffice (running writer and base)     | 1:5.2.7-1+deb9u11 |
| evince                                    | 3.22.1-3+deb9u1 |
| xfce4-terminal                            | 0.8.3-1 |

### Windows 10 x64 1511 (10586)

| Tool                                      | Version |
|-------------------------------------------|---------|
| Adobe Acrobat Reader DC                   | 2019.021.20058 |
| Chromium                                  | 81.0.4020.0 (Developer Build) (64-bit) |
| Firefox                                   | 72.0.2 (64-Bit) |
| Microsoft Edge                            | 25.10586.0.0 |
| PowerShell                                | 5.0 (Build 10586, Revision 122) |
| Microsoft Office (running Word and Excel) | Professional Plus 2019 Version 1808 (Build 10730.20102) |
