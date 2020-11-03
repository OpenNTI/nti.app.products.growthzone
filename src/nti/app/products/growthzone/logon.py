#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
.. $Id: identity.py 110862 2017-04-18 00:30:43Z carlos.sanchez $
"""

from __future__ import division
from __future__ import print_function
from __future__ import absolute_import

import os
import hashlib
import requests

import pyramid.httpexceptions as hexc

from pyramid.interfaces import IRequest

from pyramid.view import view_config

from requests.exceptions import RequestException

from requests.structures import CaseInsensitiveDict

from six.moves import urllib_parse

from simplejson import JSONDecodeError

from zope import interface
from zope import component

from zope.event import notify

from nti.app.products.growthzone import MessageFactory as _

from nti.app.products.growthzone.interfaces import IGrowthZoneUser
from nti.app.products.growthzone.interfaces import IGrowthZoneUserProfile
from nti.app.products.growthzone.interfaces import IGrowthZoneLogonSettings
from nti.app.products.growthzone.interfaces import GrowthZoneUserLogonEvent
from nti.app.products.growthzone.interfaces import GrowthZoneUserCreatedEvent

from nti.app.products.growthzone.utils import set_user_growthzone_id
from nti.app.products.growthzone.utils import get_user_for_growthzone_id

from nti.appserver.interfaces import IMissingUser
from nti.appserver.interfaces import ILogonLinkProvider
from nti.appserver.interfaces import AmbiguousUserLookupError
from nti.appserver.interfaces import IUnauthenticatedUserLinkProvider

from nti.appserver.logon import _create_success_response
from nti.appserver.logon import _create_failure_response
from nti.appserver.logon import _deal_with_external_account

from nti.appserver.policies.interfaces import INoAccountCreationEmail

from nti.dataserver.interfaces import IDataserverFolder

from nti.dataserver.users.interfaces import IUserProfile
from nti.dataserver.users.interfaces import IUsernameGeneratorUtility

from nti.dataserver.users.users import User

from nti.dataserver.users.utils import force_email_verification
from nti.dataserver.users.utils import get_users_by_email_in_sites

from nti.links.links import Link

logger = __import__('logging').getLogger(__name__)

#: The initial GROWTHZONE login rel
REL_LOGIN_GROWTHZONE = 'logon.growthzone'

#: The redirect rel after GROWTHZONE auth
LOGON_GROWTHZONE = 'logon.growthzone.oauth2'

GROWTHZONE_RETURN_URL_PARAM = 'redirect_uri'

# Saw timeouts at 1 second
_REQUEST_TIMEOUT = 4.0


def redirect_growthzone_uri(request):
    root = request.route_path('objects.generic.traversal', traverse=())
    root = root[:-1] if root.endswith('/') else root
    target = urllib_parse.urljoin(request.application_url, root)
    target = target + '/' if not target.endswith('/') else target
    target = urllib_parse.urljoin(target, LOGON_GROWTHZONE)
    return target


def redirect_growthzone2_params(request, state=None):
    """
        https://growthzoneapp.com/oauth/authorize?client_id=12345 &response_type=code
    &response_mode=form_post &redirect_uri=http://example.com/openid/callback &scope=openid+profile+email
    &state=jd8Udndha7d &nonce=93kdjdf873jdnfbnyhsgbdk
    """
    state = state or hashlib.sha256(os.urandom(1024)).hexdigest()
    auth_settings = component.getUtility(IGrowthZoneLogonSettings)
    params = {'state': state,
              'response_type': 'code',
              'response_mode': 'form_post',
              'client_id': auth_settings.client_id,
              'scope': 'openid profile email',
               GROWTHZONE_RETURN_URL_PARAM: redirect_growthzone_uri(request)}
    return params


def generate_username():
    username_util = component.getUtility(IUsernameGeneratorUtility)
    return username_util.generate_username()


def _get_auth_url():
    auth_settings = component.getUtility(IGrowthZoneLogonSettings)
    auth_url = auth_settings.login_url
    return auth_url[:-1] if auth_url.endswith('/') else auth_url


@view_config(name=REL_LOGIN_GROWTHZONE,
             route_name='objects.generic.traversal',
             context=IDataserverFolder,
             request_method='GET',
             renderer='rest')
def growthzone_oauth(request, success=None, failure=None, state=None):
    state = state or hashlib.sha256(os.urandom(1024)).hexdigest()
    params = redirect_growthzone2_params(request, state)

    for key, value in (('success', success), ('failure', failure)):
        value = value or request.params.get(key)
        if value:
            request.session['growthzone.' + key] = value

    # save state for validation
    request.session['growthzone.state'] = state

    # redirect
    target = _get_auth_url()
    target = '%s?%s' % (target, urllib_parse.urlencode(params))
    response = hexc.HTTPSeeOther(location=target)
    return response


def _return_url(request, url_type='success'):
    if url_type in request.params:
        return request.params.get(url_type)
    return request.session.get('growthzone.' + url_type)


def _get_user(external_id, email):
    """
    Get user by external id. If a user is not found, we try to find a unique
    user by email.

    Raises a `AmbiguousUserLookupError` if multiple users are found for an
    email address.
    """
    user = get_user_for_growthzone_id(external_id)
    if user is None:
        found_users = get_users_by_email_in_sites(email)
        if found_users:
            if len(found_users) > 1:
                logger.info("Cannot link growthzone account by email (%s) (%s)",
                            email, found_users)
                raise AmbiguousUserLookupError()
            else:
                # XXX: What if email address is unverified?
                user = found_users[0]
                logger.info("Linking growthzone user by email (%s) (%s)",
                            email, user)
    return user


@view_config(name=LOGON_GROWTHZONE,
             route_name='objects.generic.traversal',
             context=IDataserverFolder,
             request_method='POST',
             renderer='rest')
def growthzone_oauth2(request):
    params = dict(request.POST or {})
    params.update(request.params or {})
    # check for errors
    if 'error' in params or 'errorCode' in params:
        error = params.get('error') or params.get('errorCode')
        logger.warn('GrowthZone error during oauth (%s)', error)
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=error)

    # Confirm anti-forgery state token
    if not request.session.get('growthzone.state'):
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=_(u'Missing state.'))
    params_state = params.get('state', None)
    session_state = request.session.get('growthzone.state')
    if params_state != session_state:
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=_(u'Incorrect state values.'))

    code = params.get('code')
    if not code:
        logger.warn('GrowthZone code not found after oauth')
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=_(u'Could not find GrowthZone code.'))

    # Get our access token
    auth_settings = component.getUtility(IGrowthZoneLogonSettings)
    data = {'grant_type': 'authorization_code',
            'client_id': auth_settings.client_id,
            'client_secret': auth_settings.client_secret,
             GROWTHZONE_RETURN_URL_PARAM: redirect_growthzone_uri(request),
            'code': code}
    auth = requests.post(auth_settings.token_url,
                         data=data,
                         timeout=_REQUEST_TIMEOUT)

    try:
        auth.raise_for_status()
    except RequestException as req_ex:
        logger.exception("Failed growthzone login %s", auth.text)
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=str(req_ex))

    data = auth.json()
    if 'access_token' not in data:
        return _create_failure_response(request,
                                        _return_url(request, 'failure'),
                                        error=_(u'Could not find access token.'))
    access_token = data['access_token']
    try:
        logger.debug("Getting user profile")
        response = requests.get(auth_settings.user_info_url,
                                headers={'Authorization': 'Bearer %s' % access_token})

        try:
            response.raise_for_status()
        except RequestException as req_ex:
            logger.exception("Failed to fetch growthzone user info")
            return _create_failure_response(request,
                                            request.cookies.get(
                                                'growthzone.failure'),
                                            error=str(req_ex))

        try:
            user_info = CaseInsensitiveDict(response.json())
        except JSONDecodeError:
            # Code error? They are not giving us json
            logger.warn("Invalid user info (%s) (%s)",
                        response.status_code, response.text)
            return _create_failure_response(request,
                                            request.cookies.get(
                                                'growthzone.failure'),
                                            error=_(u'Invalid user info.'))
        if     not user_info.get('email') \
            or not user_info.get('given_name') \
            or not user_info.get('family_name') \
            or not user_info.get('sub'):
                logger.exception("Invalid growthzone user info (%s)", user_info)
                return _create_failure_response(request,
                                                request.cookies.get('growthzone.failure'),
                                                error=_(u'Invalid user info.'))
        external_id = str(user_info.get('sub'))

        try:
            user = _get_user(external_id, user_info.get('email'))
        except AmbiguousUserLookupError:
            return _create_failure_response(request,
                                            request.cookies.get('growthzone.failure'),
                                            error=_(u'Multiple users found for this email address.'))
        if user is None:
            username = generate_username()
            interface.alsoProvides(request, INoAccountCreationEmail)
            user = _deal_with_external_account(request,
                                               fname=user_info.get('given_name'),
                                               lname=user_info.get('family_name'),
                                               username=username,
                                               realname=None,
                                               email=user_info.get('email'),
                                               idurl=None,
                                               iface=None,
                                               user_factory=User.create_user,
                                               ext_values=user_info)
            set_user_growthzone_id(user, external_id, request)
            force_email_verification(user)  # trusted source
            notify(GrowthZoneUserCreatedEvent(user, request))
            request.environ['nti.request_had_transaction_side_effects'] = 'True'

        interface.alsoProvides(user, IGrowthZoneUser)
        profile = IUserProfile(user)
        interface.alsoProvides(profile, IGrowthZoneUserProfile)
        notify(GrowthZoneUserLogonEvent(user, user_info))
        response = _create_success_response(request,
                                            userid=user.username,
                                            success=_return_url(request),)
    except Exception as e:  # pylint: disable=broad-except
        logger.exception('Failed to login with growthzone')
        response = _create_failure_response(request,
                                            _return_url(request, 'failure'),
                                            error=str(e))
    return response


@component.adapter(IRequest)
@interface.implementer(IUnauthenticatedUserLinkProvider)
class SimpleUnauthenticatedUserGrowthZoneLinkProvider(object):

    rel = REL_LOGIN_GROWTHZONE

    default_title = _('Logon through GrowthZone')

    def __init__(self, request):
        self.request = request

    @property
    def title(self):
        auth_settings = component.queryUtility(IGrowthZoneLogonSettings)
        if auth_settings is not None:
            return auth_settings.logon_link_title or self.default_title

    def get_links(self):
        auth_settings = component.queryUtility(IGrowthZoneLogonSettings)
        result = []
        if auth_settings is not None:
            elements = (self.rel,)
            root = self.request.route_path('objects.generic.traversal',
                                           traverse=())
            root = root[:-1] if root.endswith('/') else root
            result.append(Link(root, elements=elements, rel=self.rel, title=self.title))
        return result


@interface.implementer(ILogonLinkProvider)
@component.adapter(IMissingUser, IRequest)
class SimpleMissingUserGrowthZoneLinkProvider(SimpleUnauthenticatedUserGrowthZoneLinkProvider):

    def __init__(self, user, request):
        super(SimpleMissingUserGrowthZoneLinkProvider, self).__init__(request)
        self.user = user

    def __call__(self):
        links = self.get_links()
        return links[0] if links else None
