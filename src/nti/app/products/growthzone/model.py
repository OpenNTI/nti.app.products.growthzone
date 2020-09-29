#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id: model.py 124702 2017-12-08 21:11:48Z carlos.sanchez $
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

from zope import interface

from nti.app.products.growthzone.interfaces import IGrowthZoneLogonSettings

from nti.schema.eqhash import EqHash

from nti.schema.fieldproperty import createDirectFieldProperties

from nti.schema.schema import SchemaConfigured

logger = __import__('logging').getLogger(__name__)


@EqHash('client_id')
@interface.implementer(IGrowthZoneLogonSettings)
class GrowthZoneLogonSettings(SchemaConfigured):
    createDirectFieldProperties(IGrowthZoneLogonSettings)

    def __str__(self):
        # pylint: disable=no-member
        return self.client_id
