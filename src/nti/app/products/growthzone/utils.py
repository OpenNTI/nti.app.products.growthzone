#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id: identity.py 110862 2017-04-18 00:30:43Z carlos.sanchez $
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

from zope import interface

from zope.event import notify

from nti.app.products.growthzone import MessageFactory as _
from nti.app.products.growthzone import raise_http_error

from nti.app.products.growthzone.interfaces import IGrowthZoneUser

from nti.externalization.interfaces import ObjectModifiedFromExternalEvent

from nti.identifiers.interfaces import IUserExternalIdentityContainer

from nti.identifiers.utils import get_user_for_external_id

logger = __import__('logging').getLogger(__name__)

PROVIDER_ID = "growthzone"


def set_user_growthzone_id(user, growthzone_id, request):
    """
    Set the given growthzone identity for a user.
    """
    if not growthzone_id:
        raise_http_error(request,
                         _(u"Must provide growthzone_id."),
                         u'NoGrowthZoneIdsGiven')
    interface.alsoProvides(user, IGrowthZoneUser)

    identity_container = IUserExternalIdentityContainer(user)
    identity_container.add_external_mapping(PROVIDER_ID, growthzone_id)
    logger.info("Setting growthzone ID for user (%s) (%s/%s)",
                user.username, PROVIDER_ID, growthzone_id)
    notify(ObjectModifiedFromExternalEvent(user))


def get_user_for_growthzone_id(growthzone_id):
    """
    Find any user associated with the given growthzone id.
    """
    return get_user_for_external_id(PROVIDER_ID, growthzone_id)
