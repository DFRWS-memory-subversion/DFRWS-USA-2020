#  Plugin to detect hidden shared memory on Linux.
#
#    Copyright (c) 2020, Frank Block, ERNW GmbH <fblock@ernw.de>
#
#       All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without modification,
#       are permitted provided that the following conditions are met:
#
#       * Redistributions of source code must retain the above copyright notice, this
#         list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above copyright notice,
#         this list of conditions and the following disclaimer in the documentation
#         and/or other materials provided with the distribution.
#       * The names of the contributors may not be used to endorse or promote products
#         derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""This plugin detects hidden shared memory on Linux.
References:
https://dfrws.org/presentation/hiding-process-memory-via-anti-forensic-techniques/
https://www.blackhat.com/us-20/briefings/schedule/index.html#hiding-process-memory-via-anti-forensic-techniques-20661
"""

__author__ = "Frank Block <fblock@ernw.de>"

from rekall.plugins.linux import common


def is_tmpfs_file(file_struct):
    """We are currently concentrating on tmpfs shared memory."""
    if not file_struct:
        return False

    return file_struct.f_mapping.host.type == "S_IFREG" and \
            file_struct.vfsmnt.mnt_sb.s_id == "tmpfs"


class HiddenSharedMemoryDetectorLinux(common.LinProcessFilter):
    """Implements the detection of hidden executable shared memory.
    """

    name = "detect_hidden_shmem"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", width=12),
        dict(name="file_object", style="address", width=16),
        dict(name="devname", width=48),

    ]


    def collect(self):
        cc = self.session.plugins.cc()

        for task in self.filter_processes():
            if not task.mm.dereference():
                continue

            cc.SwitchProcessContext(task)

            address_spaces = dict()
            vma_address_spaces = set()

            ### First we generate a list of all file objects mapped in vmas
            for vma in task.mm.mmap.walk_list("vm_next"):
                if vma.vm_file:
                    vma_address_spaces.add(vma.vm_file.f_mapping.deref())

            ### Now we gather all shared memory objects related to the proc obj
            # First, memfd and mmap scenario file objects
            for file_ptr in task.files.fds:
                file_struct = file_ptr.deref()
                if is_tmpfs_file(file_struct):
                    address_spaces[file_struct.f_mapping.deref()] = file_struct

            ### Second, all SYSTEM V type shared objects
            for shmid_kernel_object in task.sysvshm.shm_clist.list_of_type("shmid_kernel", "shm_clist"):
                file_struct = shmid_kernel_object.shm_file.dereference()
                if is_tmpfs_file(file_struct):
                    address_spaces[file_struct.f_mapping.deref()] = file_struct

            # TODO Add functionality to dump data

            address_spaces_set = set(address_spaces.keys())
            for address_space in address_spaces_set.difference(vma_address_spaces):
                yield dict(task=task.pid,
                           file_object=address_spaces[address_space].v(),
                           devname=task.get_path(address_spaces[address_space])
                          )
