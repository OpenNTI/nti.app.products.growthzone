#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id: identity.py 110862 2017-04-18 00:30:43Z carlos.sanchez $
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

import requests

from requests.exceptions import RequestException

from requests.structures import CaseInsensitiveDict

from simplejson import JSONDecodeError

from zope import component

from nti.contenttypes.courses.interfaces import ES_PURCHASED

from nti.contenttypes.courses.interfaces import ICourseCatalog
from nti.contenttypes.courses.interfaces import ICourseInstance
from nti.contenttypes.courses.interfaces import ICourseEnrollmentManager

from nti.contenttypes.courses.utils import is_enrolled_in_hierarchy

logger = __import__('logging').getLogger(__name__)


def _get_company_id(access_token, auth_settings):
    """
    Returns the user's str company id or None.
    """
    logger.debug("Getting user aboutme")
    response = requests.get(auth_settings.aboutme_url,
                            headers={'Authorization': 'Bearer %s' % access_token})

    try:
        response.raise_for_status()
    except RequestException:
        logger.exception("Failed to fetch growthzone user aboutme info")
        return

    try:
        aboutme_info = CaseInsensitiveDict(response.json())
    except JSONDecodeError:
        # Code error? They are not giving us json
        logger.warn("Invalid aboutme info (%s) (%s)",
                    response.status_code, response.text)
    else:
        return aboutme_info.get('CurrentOrganizationId'), aboutme_info.get('ContactId')


def _get_puids_from_descriptions(descs):
    """
    From a sequence of str purchase descriptions, capture the possible
    provider unique ids in a set with all values in lowercase.

    Ex: u'CMA CEU Online #CMACEU21-1 - Anthony Tarleton - Online CMA Class - Unknown'
    """
    result = set()
    for desc in descs:
        desc = desc.split(' - ')[0]
        puid = desc.split('#')[-1]
        if puid:
            result.add(puid.lower())
    return result


def _get_billing_provider_unique_ids(company_id, access_token, auth_settings):
    """
    Returns the purchase indicated provider unique ids.
    """
    logger.debug("Getting user aboutme")
    company_purchases_url = auth_settings.company_purchases_url % company_id
    response = requests.get(company_purchases_url,
                            headers={'Authorization': 'Bearer %s' % access_token})

    try:
        response.raise_for_status()
    except RequestException:
        logger.exception("Failed to fetch growthzone company purchases")
        return

    try:
        purchases_res = CaseInsensitiveDict(response.json())
    except JSONDecodeError:
        # Code error? They are not giving us json
        logger.warn("Invalid company purchases (%s) (%s)",
                    response.status_code, response.text)
        return

    purchase_descriptions = set()
    for purchase_dict in purchases_res.get('Results') or ():
        # XXX: Could filter by type
        for detail_item in purchase_dict.get('DetailItems') or ():
            desc = detail_item.get('Description')
            if desc:
                logger.debug("Adding desc (%s) (%s)",
                             desc, detail_item.get('Type'))
                purchase_descriptions.add(desc)
    result = _get_puids_from_descriptions(purchase_descriptions)
    return result


def update_enrollments(user, access_token, auth_settings):
    """
    Given a user object, access_token, and GZ auth settings, update the
    user's enrollments.

    We will log any API related errors
    """
    company_id, contact_id = _get_company_id(access_token, auth_settings)
    if company_id:
        logger.info("Retrieving purchases for company (%s) (%s)",
                    company_id, user.username)
        puids = _get_billing_provider_unique_ids(company_id,
                                                 access_token,
                                                 auth_settings)
    else:
        # We need to get puids for non-company tied users.
        logger.info("Retrieving purchases for user (%s) (%s)",
                    company_id, user.username)
        puids = _get_billing_provider_unique_ids(contact_id,
                                                 access_token,
                                                 auth_settings)
    if not puids:
        return
    # Now handle enrollment
    processed_puids = set()
    logger.info("Processing enrollments for GZ user (%s) (%s)",
                user.username,
                puids)
    course_catalog = component.getUtility(ICourseCatalog)
    for entry in course_catalog.iterCatalogEntries():
        if      entry.ProviderUniqueID \
            and entry.ProviderUniqueID.lower() in puids:
            found_puid = entry.ProviderUniqueID.lower()
            processed_puids.add(found_puid)
            logger.debug("Checking enrollment for (%s) (%s) (%s)",
                         user.username, found_puid, entry.ntiid)
            course = ICourseInstance(entry)
            if not is_enrolled_in_hierarchy(course, user):
                logger.info("Enrolling user (%s) (%s) (%s)",
                            user.username, found_puid, entry.ntiid)
                enrollment_manager = ICourseEnrollmentManager(course)
                enrollment_manager.enroll(user, ES_PURCHASED)
    missing = puids - processed_puids
    if missing:
        logger.info('Could not find courses to enroll user in (%s) (%s)',
                    user.username,
                    missing)
