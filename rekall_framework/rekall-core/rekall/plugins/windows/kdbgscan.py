# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
# pylint: disable=protected-access

from rekall import obj
from rekall import scan
from rekall import plugin

from rekall.plugins.windows import common
from rekall_lib import utils


class KDBGScanner(scan.BaseScanner):
    """Scans for _KDDEBUGGER_DATA64 structures.

    Note that this does not rely on signatures, as validity of hits is
    calculated through list reflection.
    """
    checks = [("StringCheck", dict(needle=b"KDBG"))]

    def scan(self, offset=0, maxlen=None):
        maxlen = maxlen or self.profile.get_constant("MaxPointer")

        # How far into the struct the OwnerTag is.
        owner_tag_offset = self.profile.get_obj_offset(
            "_DBGKD_DEBUG_DATA_HEADER64", "OwnerTag")

        # Depending on the memory model this behaves slightly differently.
        architecture = self.profile.metadata("arch", "I386")

        # This basically iterates over all hits on the string "KDBG".
        for offset in super(KDBGScanner, self).scan(offset, maxlen):
            # For each hit we overlay a _DBGKD_DEBUG_DATA_HEADER64 on it and
            # reflect through the "List" member.
            result = self.profile.Object("_KDDEBUGGER_DATA64",
                                         offset=offset - owner_tag_offset,
                                         vm=self.address_space)

            # We verify this hit by reflecting through its header list.
            list_entry = result.Header.List

            # On 32 bit systems the Header.List member seems to actually be a
            # LIST_ENTRY32 instead of a LIST_ENTRY64, but it is still padded to
            # take the same space:
            if architecture == "I386":
                list_entry = list_entry.cast("LIST_ENTRY32")

            if list_entry.reflect():
                yield result

            elif (list_entry.Flink == list_entry.Blink and
                  not list_entry.Flink.dereference()):
                self.session.logging.debug(
                    "KDBG list_head is not mapped, assuming its valid.")

                yield result


class KDBGScan(plugin.KernelASMixin, common.AbstractWindowsCommandPlugin):
    """Scan for possible _KDDEBUGGER_DATA64 structures.

    The scanner is detailed here:
    http://moyix.blogspot.com/2008/04/finding-kernel-global-variables-in.html

    The relevant structures are detailed here:
    http://doxygen.reactos.org/d3/ddf/include_2psdk_2wdbgexts_8h_source.html

    We can see that _KDDEBUGGER_DATA64.Header is:

    typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
        LIST_ENTRY64    List;
        ULONG           OwnerTag;
        ULONG           Size;
    }

    We essentially search for an owner tag of "KDBG", then overlay the
    _KDDEBUGGER_DATA64 struct on it. We test for validity by reflecting
    through the Header.List member.
    """

    __name = "kdbgscan"

    __args = [
        dict(name="full_scan", type="Boolean",
             help="Scan the full address space.")
    ]

    def hits(self):
        if self.plugin_args.full_scan:
            start, end = 0, 2**64
        else:
            # The kernel image is always loaded in the same range called the
            # "Initial Loader Mappings". Narrowing the possible range makes
            # scanning much faster. (See
            # http://www.codemachine.com/article_x64kvas.html)
            if self.session.profile.metadata("arch") == "AMD64":
                start, end = 0xFFFFF80000000000, 0xFFFFF87FFFFFFFFF
            else:
                start, end = 0x80000000, 0xFFFFFFFF

        scanner = KDBGScanner(
            session=self.session, profile=self.profile,
            address_space=self.kernel_address_space)

        # Yield actual objects here
        for kdbg in scanner.scan(
                obj.Pointer.integer_to_address(start),
                end - start):
            yield kdbg

    table_header = [
        dict(name="Key", width=50),
        dict(name="Value")
    ]

    table_options = dict(
        suppress_headers=True
    )

    def collect(self):
        """Renders the KPCR values as text"""

        for kdbg in self.hits():
            yield "Offset (V)", utils.HexInteger(kdbg.obj_offset)
            yield "Offset (P)", utils.HexInteger(kdbg.obj_vm.vtop(
                kdbg.obj_offset))

            # These fields can be gathered without dereferencing
            # any pointers, thus they're available always
            yield "KDBG owner tag check", kdbg.is_valid()

            verinfo = kdbg.dbgkd_version64()
            if verinfo:
                yield "Version64", "{0:#x} (Major: {1}, Minor: {2})\n".format(
                    verinfo.obj_offset, verinfo.MajorVersion,
                    verinfo.MinorVersion)

            yield "Service Pack (CmNtCSDVersion)", kdbg.ServicePack
            yield "Build string (NtBuildLab)", kdbg.NtBuildLab.dereference()

            # Count the total number of tasks from PsActiveProcessHead.
            try:

                pslist = kdbg.PsActiveProcessHead.list_of_type(
                    "_EPROCESS", "ActiveProcessLinks")
                num_tasks = len([x for x in pslist if x.pid > 0])
            except AttributeError:
                num_tasks = 0

            try:
                modules = self.session.plugins.modules(session=self.session)
                num_modules = len(list(modules.lsmod()))
            except AttributeError:
                num_modules = 0

            yield "PsActiveProcessHead", "{0:#x} ({1} processes)".format(
                kdbg.PsActiveProcessHead, num_tasks)

            yield "PsLoadedModuleList", "{0:#x} ({1} modules)".format(
                kdbg.PsLoadedModuleList, num_modules)

            yield "KernelBase", "{0:#x} (Matches MZ: {1})".format(
                kdbg.KernBase, kdbg.obj_vm.read(kdbg.KernBase, 2) == b"MZ")

            # Parse the PE header of the kernel.
            pe_profile = self.session.LoadProfile("pe")

            dos_header = pe_profile._IMAGE_DOS_HEADER(
                offset=kdbg.KernBase, vm=kdbg.obj_vm)
            nt_header = dos_header.NTHeader
            if nt_header:
                yield ("Major (OptionalHeader)",
                       nt_header.OptionalHeader.MajorOperatingSystemVersion)

                yield("Minor (OptionalHeader)",
                      nt_header.OptionalHeader.MinorOperatingSystemVersion)

            # The CPU block.
            for kpcr in kdbg.kpcrs():
                yield "KPCR", "{0:#x} (CPU {1})".format(
                    kpcr.obj_offset, kpcr.ProcessorBlock.Number)
