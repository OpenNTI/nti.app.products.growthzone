#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id$
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

# pylint: disable=inherit-non-class,expression-not-assigned

from zope import interface

from zope.interface import Attribute

from zope.interface.interfaces import ObjectEvent
from zope.interface.interfaces import IObjectEvent

from nti.schema.field import ValidTextLine as TextLine


class IGrowthZoneUser(interface.Interface):
    """
    Marker interface for a user created via GrowthZone.
    """


class IGrowthZoneLogonSettings(interface.Interface):

    api_endpoint = TextLine(title=u"The growthzone API url", required=True)

    api_key = TextLine(title=u"The growthzone api key", required=True)


class IGrowthZoneUserCreatedEvent(IObjectEvent):
    """
    Fired after an Google user has been created
    """
    request = Attribute(u"Request")


@interface.implementer(IGrowthZoneUserCreatedEvent)
class GrowthZoneUserCreatedEvent(ObjectEvent):

    def __init__(self, obj, request=None):
        super(GrowthZoneUserCreatedEvent, self).__init__(obj)
        self.request = request


class GrowthZoneException(Exception):
    """
    A generic growthzone API exception.
    """


class GrowthZoneSessionException(GrowthZoneException):
    """
    A growthzone API error when fetching a session.
    """


class GrowthZoneAuthTokenException(GrowthZoneException):
    """
    A growthzone API error when fetching an auth token.
    """


class GrowthZoneUserInfoException(GrowthZoneException):
    """
    An exception indicating we received an error when fetching GrowthZone
    user info.
    """


class GrowthZoneUserInfoNotFoundException(GrowthZoneUserInfoException):
    """
    An exception indicating we received a user info response but no user info
    data.
    """
