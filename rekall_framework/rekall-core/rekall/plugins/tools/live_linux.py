#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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

__author__ = "Michael Cohen <scudette@google.com>"

"""A plugin to install relevant kernel modules to enable live analysis.

The intention is to allow the user to launch:

rekall live

and have Rekall install the right kernel module and connect to the driver on all
supported operating systems.
"""
import os

from rekall import plugin
from rekall import session

from rekall.plugins.addrspaces import standard


class Live(plugin.TypedProfileCommand,
           plugin.ProfileCommand):
    """Launch a Rekall shell for live analysis on the current system."""

    name = "live"

    PROFILE_REQUIRED = False

    __args = [
        dict(name="mode", default="Memory", type="Choices",
             choices=session.LIVE_MODES,
             help="Mode for live analysis."),
    ]

    def live(self):
        if os.geteuid() != 0:
            self.session.logging.error(
                "You are not root. It is likely that some operations "
                "may not be available.")

        # Force timed cache for live sessions.
        with self.session:
            self.session.SetParameter("cache", "timed")
            self.session.SetParameter("live_mode", self.plugin_args.mode)
            self.session.SetParameter("session_name", "Live (%s)" %
                                      self.plugin_args.mode)

            if self.plugin_args.mode == "Memory":
                try:
                    # Stack the address spaces by hand.
                    load_as = self.session.plugins.load_as(session=self.session)
                    base_as = standard.FileAddressSpace(session=self.session,
                                                        filename="/proc/kcore")

                    self.session.physical_address_space = (
                        load_as.GuessAddressSpace(base_as=base_as))

                    self.session.SetParameter("session_name",
                                              "Live(/proc/kcore)")

                except IOError as e:
                    self.session.logging.error(
                        "Unable to load physical memory: %s ", e)


    def close(self):
        pass

    def __str__(self):
        # The default __str__ form will run the plugin which will drop into a
        # shell!
        return u"Live Plugin"

    def __enter__(self):
        self.live()
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.close()

    def collect(self, renderer):
        renderer.format("Launching live memory analysis\n")
        self.live()

        # Launch the shell.
        shell = self.session.plugins.shell()
        shell.render(renderer)
