"""Add a magic handler for select, describe and explain plugins."""
from IPython.core import magic
from rekall import ipython_support


@magic.magics_class
class EfilterMagics(magic.Magics):

    def _RunPlugin(self, session, plugin_name, line):
        # Strip quotes.
        while line[0] == line[-1] and line[0] in "'\"":
            line = line[1:-1]

        return session.RunPlugin(plugin_name, query=line)

    @magic.line_cell_magic
    def SELECT(self, line, cell=None):
        return self._process_select(line, cell)

    @magic.line_cell_magic
    def select(self, line, cell=None):
        """This makes it easier to run the search plugin:

[1] win7.elf 15:35:09> select * from pslist() where _EPROCESS.name =~ "svchost"
  _EPROCESS            Name          PID   PPID   Thds    Hnds    Sess  Wow64
-------------- -------------------- ----- ------ ------ -------- ------ ------
0xfa80024f85d0 svchost.exe            236    480     19      455      0 False
0xfa80023f6770 svchost.exe            608    480     12      352      0 False
        """
        return self._process_select(line, cell)

    def _process_select(self, line, cell=None):
        session = self.shell.user_module.session
        return self._RunPlugin(session, "search", "select " + line + (
            cell or ""))

    @magic.line_cell_magic
    def pager(self, line, cell=None):
        session = self.shell.user_module.session
        if " " in line:
            _, line_end = line.split(" ", 1)
        else:
            # A bare pager magic with pager already set, means to clear it.
            if session.GetParameter("pager"):
                session.SetParameter("pager", None)
                return

            line_end = "less"

        session.SetParameter("pager", line_end)


ipython_support.REGISTERED_MAGICS.append(EfilterMagics)
