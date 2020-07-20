#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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
import logging
from multiprocessing.pool import ThreadPool
from rekall import config
from rekall import plugin


config.DeclareOption("agent_configuration", group="Rekall Agent",
                     help="The Rekall Agent configuration file. When "
                     "specified Rekall switches to Agent mode.")


class Interpolator(dict):
    """A commonly used format interpolator for locations.

    The below supports path template interpolations allowing various
    expansions to be made dynamically. For example a file path
    template may include "/path{client_id}/foo" to expand the
    client_id into the path.
    """
    def __init__(self, session, **kwargs):
        super(Interpolator, self).__init__(**kwargs)
        self.session = session
        self._config = session.GetParameter("agent_config_obj")

    def __getitem__(self, item):
        if item in self:
            return self.get(item)

        return getattr(self, "get_" + item, None)()

    def get_client_id(self):
        return self._config.client.writeback.client_id

    def get_last_flow_time(self):
        return self._config.client.writeback.last_flow_time

    def get_nonce(self):
        return self._config.client.nonce


class AgentConfigMixin(object):

    @property
    def _config(self):
        session = getattr(self, "_session", None) or getattr(self, "session")
        return session.GetParameter("agent_config_obj")


class LogExceptions(object):
    def __init__(self, callable):
        self.__callable = callable

    def __call__(self, *args, **kwargs):
        try:
            result = self.__callable(*args, **kwargs)
        except Exception as e:
            logging.exception(e)
            raise

        # It was fine, give a normal answer
        return result


class LoggingPool(ThreadPool):
    """The default threadpool swallows exceptions."""

    def apply_async(self, func, *args, **kwargs):
        return super(LoggingPool, self).apply_async(
            LogExceptions(func), *args, **kwargs)

    def imap_unordered(self, func, *args, **kwargs):
        return super(LoggingPool, self).imap_unordered(
            LogExceptions(func), *args, **kwargs)

    def map(self, func, *args, **kwargs):
        return super(LoggingPool, self).map(
            LogExceptions(func), *args, **kwargs)


# A threadpool for reading all messages from a the ticket queue efficiently.
THREADPOOL = LoggingPool(100)



class AbstractAgentCommand(AgentConfigMixin, plugin.TypedProfileCommand,
                           plugin.Command):
    """All commands running on the rekall agent extend this."""
    __abstract = True

    PHYSICAL_AS_REQUIRED = False
    PROFILE_REQUIRED = False

    mode = "mode_agent"

    __args = []
