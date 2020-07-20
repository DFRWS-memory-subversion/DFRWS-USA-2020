# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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

from builtins import str
__author__ = "Michael Cohen <scudette@google.com>"


from rekall.ui import text
from rekall.plugins.renderers import data_export
from rekall_lib import utils


class FileSpec_Text(text.TextObjectRenderer):
    renders_type = "FileSpec"

    def render_row(self, target, width=None, **_):
        if target.filesystem == "API":
            return text.Cell(str(target.name), width=width)

        else:
            return text.Cell(u"%s (%s)" % (target.name, target.filesystem),
                             width=width)


class FileInformation_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "FileInformation"

    def render_row(self, target, **options):
        return FileSpec_Text(
            renderer=self.renderer, session=self.session).render_row(
                target.filename, **options)


class UserTextObjectRenderer(text.TextObjectRenderer):
    renders_type = "User"

    def render_row(self, item, **_):
        if item.username:
            return text.Cell(u"%s (%s)" % (item.username, item.uid))
        return text.Cell(str(item.uid))


class GroupTextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Group"

    def render_row(self, item, **_):
        if item.group_name:
            return text.Cell(u"%s (%s)" % (item.group_name, item.gid))
        return text.Cell(str(item.gid))


class DataExportFileSpecObjectRenderer(
        data_export.DataExportBaseObjectRenderer):
    renders_type = "FileSpec"

    def Summary(self, item, **_):
        return utils.SmartStr(item)

    def GetState(self, item, **options):
        return dict(filesystem=item.filesystem, name=item.name)


class PermissionsFileSpecObjectRenderer(
        data_export.DataExportBaseObjectRenderer):
    renders_type = "Permissions"

    def Summary(self, item, **_):
        return utils.SmartStr(item)

    def GetState(self, item, **options):
        return dict(perm=str(item), int_perm=int(item))


class LiveProcessTextRenderer(text.TextObjectRenderer):
    renders_type = "LiveProcess"

    def render_row(self, target, width=None, **_):
        return text.Cell("%s (%s)" % (target.name, target.pid), width=width)

class LiveProcessDataExportRenderer(
        data_export.DataExportBaseObjectRenderer):
    renders_type = "LiveProcess"

    def GetState(self, item, **_):
        return item.as_dict()
