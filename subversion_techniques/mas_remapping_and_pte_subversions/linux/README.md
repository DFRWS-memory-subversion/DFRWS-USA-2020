Example usage after checkout:

    rmmod rootkit_evil ; cd /root/kernel_module; make clean ; make all && insmod /root/kernel_module/rootkit_evil.ko && cd /root/user_space_tool && make all && ./norm-process


Possible commands in interactive mode are:

    load_pteremapping
    load_pteerasure
    load_masremapping
    reveal_data
    hide_data
    run_shellcode


Example sequence:

    load_pteremapping

    # Test successful execution:
    run_shellcode

    # Scan process e.g. with yara to verify memory can't be found

    # Then temporarily reveal hidden data:
    reveal_data

    # Scan again: Malicious memory should be identifiable

    # Rehide:
    hide_data
