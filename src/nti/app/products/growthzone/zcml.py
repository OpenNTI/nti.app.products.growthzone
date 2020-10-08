#!/usr/bin/env python
# -*- coding: utf-8 -*
"""
.. $Id: zcml.py 124707 2017-12-08 21:48:18Z carlos.sanchez $
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

# pylint: disable=inherit-non-class

import functools

from pyramid.interfaces import IRequest

from zope import interface

from zope.component.zcml import utility
from zope.component.zcml import adapter
from zope.component.zcml import subscriber

from zope.schema import TextLine

from zope.traversing.interfaces import IPathAdapter

from nti.app.products.growthzone.interfaces import IGrowthZoneLogonSettings

from nti.app.products.growthzone.logon import SimpleMissingUserGrowthZoneLinkProvider
from nti.app.products.growthzone.logon import SimpleUnauthenticatedUserGrowthZoneLinkProvider

from nti.app.products.growthzone.model import GrowthZoneLogonSettings

from nti.appserver.account_creation_views import DenyAccountCreatePathAdapter
from nti.appserver.account_creation_views import DenyAccountCreatePreflightPathAdapter

from nti.appserver.interfaces import ILogonLinkProvider
from nti.appserver.interfaces import IUnauthenticatedUserLinkProvider

from nti.common._compat import text_

from nti.common.cypher import get_plaintext

from nti.coremetadata.interfaces import IMissingUser

from nti.dataserver.interfaces import IDataserverFolder

from nti.schema.field import Bool
from nti.schema.field import HTTPURL

logger = __import__('logging').getLogger(__name__)


class IRegisterGrowthZoneLogonSettings(interface.Interface):

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


def registerGrowthZoneLogonSettings(_context, client_id,
                                    client_secret,
                                    login_url,
                                    user_info_url,
                                    token_url, logon_link_title):
    """
    Register growthzone logon settings, including link providers. Disables
    account creation if necessary.
    """
    factory = functools.partial(GrowthZoneLogonSettings,
                                client_id=text_(client_id),
                                client_secret=get_plaintext(client_secret),
                                login_url=login_url,
                                user_info_url=user_info_url,
                                token_url=token_url,
                                logon_link_title=logon_link_title)
    utility(_context, provides=IGrowthZoneLogonSettings, factory=factory)

    subscriber(_context, provides=ILogonLinkProvider,
               for_=(IMissingUser, IRequest),
               factory=SimpleMissingUserGrowthZoneLinkProvider)
    subscriber(_context, provides=IUnauthenticatedUserLinkProvider,
               for_=(IRequest,),
               factory=SimpleUnauthenticatedUserGrowthZoneLinkProvider)
