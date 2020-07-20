#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Arkadiusz Socała <as277575@mimuw.edu.pl>
# Michael Cohen <scudette@google.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

import mock
from layout_expert.c_ast import visitor_mixin


class TestVisitorMixin(unittest.TestCase):

    class MockSubclass(visitor_mixin.VisitorMixin):
        pass

    def test_accept(self):
        visitor = mock.MagicMock()
        visitor.visit_visitor_mixin.return_value = -2
        visitor_mixin_instance = visitor_mixin.VisitorMixin()
        actual = visitor_mixin_instance.accept(visitor, 42, foo=33)
        self.assertEqual(actual, -2)
        visitor.visit_visitor_mixin.assert_called_with(
            visitor_mixin_instance,
            42,
            foo=33,
        )

    def test_accept_with_mock_subclass(self):
        visitor = mock.MagicMock()
        visitor.visit_mock_subclass.return_value = 7
        subclass_instance = self.MockSubclass()
        actual = subclass_instance.accept(visitor, 33, 42, bar='baz')
        self.assertEqual(actual, 7)
        visitor.visit_mock_subclass.assert_called_with(
            subclass_instance,
            33,
            42,
            bar='baz',
        )


if __name__ == '__main__':
    unittest.main()
