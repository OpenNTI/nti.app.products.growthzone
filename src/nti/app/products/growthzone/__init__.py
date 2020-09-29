#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id$
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

import zope.i18nmessageid
MessageFactory = zope.i18nmessageid.MessageFactory(__name__)

from pyramid import httpexceptions as hexc

from nti.app.externalization.error import raise_json_error


def raise_http_error(request, message, code, factory=hexc.HTTPUnprocessableEntity):
    """
    Raise an HTTP json error.
    """
    raise_json_error(request,
                     factory,
                     {
                         'message': message,
                         'code': code,
                     },
                     None)
