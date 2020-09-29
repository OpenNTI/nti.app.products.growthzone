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

from nti.schema.field import HTTPURL
from nti.schema.field import ValidTextLine as TextLine


class IGrowthZoneUser(interface.Interface):
    """
    Marker interface for a user created via GrowthZone.
    """


class IGrowthZoneUserProfile(interface.Interface):
    """
    Marker interface for a user created via GrowthZone.
    """


class IGrowthZoneLogonSettings(interface.Interface):

    client_id = TextLine(title=u'The OAuth2 client id',
                         required=True)

    client_secret = TextLine(title=u'The OAuth2 client secret',
                             required=True)

    login_url = HTTPURL(title=u'The url the client should be sent to in order to initiate the log in process',
                        required=True)

    token_url = HTTPURL(title=u'The token url',
                        required=True)

    user_info_url = HTTPURL(title=u'The url to fetch user information',
                            required=True)

    logon_link_title = TextLine(title=u'The logon link title',
                                required=False)


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


class IGrowthZoneUserLogonEvent(IObjectEvent):
    """
    Fired after an growthzone user has logged on
    """
    request = Attribute(u"Request")


@interface.implementer(IGrowthZoneUserLogonEvent)
class GrowthZoneUserLogonEvent(ObjectEvent):

    def __init__(self, obj, external_values=None, request=None):
        super(GrowthZoneUserLogonEvent, self).__init__(obj)
        self.request = request
        self.external_values = external_values or {}

