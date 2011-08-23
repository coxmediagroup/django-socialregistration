import uuid
import urllib
import facebook
import logging

from django.conf import settings
from django.template import RequestContext
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.utils.translation import gettext as _
from django.http import HttpResponseRedirect

try:
    from django.views.decorators.csrf import csrf_protect
    has_csrf = True
except ImportError:
    has_csrf = False

from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout as auth_logout
from django.contrib.sites.models import Site

from socialregistration.forms import UserForm, ClaimForm, ExistingUser
from socialregistration.utils import (OAuthClient, OAuthTwitter,
    OpenID, _https, DiscoveryFailure, GoogleOpenIDSchemas, YahooOpenIDSchemas, MyOpenIDSchemas)
from socialregistration.models import FacebookProfile, TwitterProfile, OpenIDProfile

from openid.extensions import ax, pape, sreg
from urlparse import urljoin
from django.db import connection
from django.core.urlresolvers import reverse as reverseURL
from socialregistration import util
from openid.consumer import consumer

FB_ERROR = _('We couldn\'t validate your Facebook credentials')

GENERATE_USERNAME = bool(getattr(settings, 'SOCIALREGISTRATION_GENERATE_USERNAME', False))
logger = logging.getLogger(__name__)

def _get_next(request):
    """
    Returns a url to redirect to after the login
    """
    if 'next' in request.session:
        next = request.session['next']
        del request.session['next']
        return next
    elif 'next' in request.GET:
        return request.GET.get('next')
    elif 'next' in request.POST:
        return request.POST.get('next')
    else:
        return getattr(settings, 'LOGIN_REDIRECT_URL', '/')

def setup(request, template='socialregistration/setup.html',
    form_class=UserForm, extra_context=dict(), claim_form_class=ClaimForm):
    """
    Setup view to create a username & set email address after authentication
    """
    try:
        social_user = request.session['socialregistration_user']
        social_profile = request.session['socialregistration_profile']
    except KeyError:
        return render_to_response(
            template, dict(error=True), context_instance=RequestContext(request))

    if not GENERATE_USERNAME:
        # User can pick own username
        if not request.method == "POST":
            form = form_class(social_user, social_profile,)
        else:
            form = form_class(social_user, social_profile, request.POST)
            try:
                if form.is_valid():
                    form.save()
                    user = form.profile.authenticate()
                    login(request, user)

                    del request.session['socialregistration_user']
                    del request.session['socialregistration_profile']

                    return HttpResponseRedirect(_get_next(request))
            except ExistingUser:
                # see what the error is. if it's just an existing user, we want to let them claim it.
                if 'submitted' in request.POST:
                    form = claim_form_class(
                        request.session['socialregistration_user'],
                        request.session['socialregistration_profile'],
                        request.POST
                    )
                else:
                    form = claim_form_class(
                        request.session['socialregistration_user'],
                        request.session['socialregistration_profile'],
                        initial=request.POST
                    )

                if form.is_valid():
                    form.save()

                    user = form.profile.authenticate()
                    login(request, user)

                    del request.session['socialregistration_user']
                    del request.session['socialregistration_profile']

                    return HttpResponseRedirect(_get_next(request))

                extra_context['claim_account'] = True

        extra_context.update(dict(form=form))

        return render_to_response(template, extra_context,
            context_instance=RequestContext(request))

    else:
        # Generate user and profile
        social_user.username = str(uuid.uuid4())[:30]
        social_user.save()

        social_profile.user = social_user
        social_profile.save()

        # Authenticate and login
        user = social_profile.authenticate()
        login(request, user)

        # Clear & Redirect
        del request.session['socialregistration_user']
        del request.session['socialregistration_profile']
        return HttpResponseRedirect(_get_next(request))

if has_csrf:
    setup = csrf_protect(setup)

def facebook_oauth_login(request, template='socialregistration/facebook.html',
    extra_context={}):
    """ View to handle the facebook oauth login process """
    if request.REQUEST.get("device"):
        device = request.REQUEST.get("device")
    else:
        device = "user-agent"

    params = {}
    params["client_id"] = getattr(settings, "FACEBOOK_APP_ID")
    params["redirect_uri"] = request.build_absolute_uri(reverse("facebook_oauth_login_done"))
    params['scope'] = getattr(settings, "FACEBOOK_SCOPE")
    url = "https://graph.facebook.com/oauth/authorize?"+urllib.urlencode(params)
    request.session["next"] = _get_next(request)
    return HttpResponseRedirect(url)

def facebook_oauth_login_done(request, template="socialregistration.facebook.html",
    extra_context={}, account_inactive_template="socialregistration/account_inactive.html"):
    """ Handle the oauth callback with requested account information and params """
    user = authenticate(request=request)
    app_id = getattr(settings, "FACEBOOK_APP_ID")
    logger.debug("User is %s" % user)
    logger.debug(request.session.items())
    if user is None:
        logger.debug("No User")
        # Facebook Authentication Failed
        request.COOKIES.pop(app_id + "_session_key", None)
        request.COOKIES.pop(app_id + "_user", None)
        extra_context.update({"error" : FB_ERROR})
        return HttpResponseRedirect(reverse("login"))

    elif not user.pk:
        logger.debug("No User PK")
        # New user was created
        request.session['next'] = _get_next(request)
        return HttpResponseRedirect(reverse('socialregistration_setup'))

    elif not user.is_active:
        logger.debug("user not active")
        return render_to_response(account_inactive_template, extra_context,
            context_instance=RequestContext(request))
    logger.debug("loggin in")
    login(request, user)

    return HttpResponseRedirect(_get_next(request))

#def facebook_login(request, template='socialregistration/facebook.html',
#    extra_context=dict(), account_inactive_template='socialregistration/account_inactive.html'):
#    """
#    View to handle the Facebook login
#    """
#    
#    if request.facebook.uid is None:
#        extra_context.update(dict(error=FB_ERROR))
#        return HttpResponseRedirect(reverse('login'))
#
#    user = authenticate(uid=request.facebook.uid)
#
#    if user is None:
#        request.session['socialregistration_user'] = User()
#        request.session['socialregistration_profile'] = FacebookProfile(uid=request.facebook.uid)
#        request.session['next'] = _get_next(request)
#        return HttpResponseRedirect(reverse('socialregistration_setup'))
#
#    if not user.is_active:
#        return render_to_response(account_inactive_template, extra_context,
#            context_instance=RequestContext(request))
#
#    login(request, user)
#
#    return HttpResponseRedirect(_get_next(request))

def facebook_connect(request, template='socialregistration/facebook.html',
    extra_context=dict()):
    """
    View to handle connecting existing django accounts with facebook
    """
    cookie = facebook.get_user_from_cookie(request.COOKIES, FACEBOOK_APP_ID, FACEBOOK_SECRET_KEY)
    
    if not cookie or request.user.is_authenticated() is False:
        extra_context.update(dict(error=FB_ERROR))
        return render_to_response(template, extra_context,
            context_instance=RequestContext(request))

    try:
        params = {"access_token" : cookie['access_token']}
        url = 'https://graph.facebook.com/me?' + urllib.urlencode(params)
        user_data = simplejson.load(urllib.urlopen(url))
        profile = FacebookProfile.objects.get(uid=user_data["id"])
    except FacebookProfile.DoesNotExist:
        profile = FacebookProfile.objects.create(user=request.user,
            uid=user_data["id"])

    return HttpResponseRedirect(_get_next(request))

def logout(request, redirect_url=None):
    """
    Logs the user out of django. This is only a wrapper around
    django.contrib.auth.logout. Logging users out of Facebook for instance
    should be done like described in the developer wiki on facebook.
    http://wiki.developers.facebook.com/index.php/Connect/Authorization_Websites#Logging_Out_Users
    """
    auth_logout(request)

    url = redirect_url or getattr(settings, 'LOGOUT_REDIRECT_URL', '/')

    return HttpResponseRedirect(url)

def twitter(request, account_inactive_template='socialregistration/account_inactive.html',
    extra_context=dict()):
    """
    Actually setup/login an account relating to a twitter user after the oauth
    process is finished successfully
    """
    client = OAuthTwitter(
        request, settings.TWITTER_CONSUMER_KEY,
        settings.TWITTER_CONSUMER_SECRET_KEY,
        settings.TWITTER_REQUEST_TOKEN_URL,
    )

    user_info = client.get_user_info()

    if request.user.is_authenticated():
        # Handling already logged in users connecting their accounts
        try:
            profile = TwitterProfile.objects.get(twitter_id=user_info['id'])
        except TwitterProfile.DoesNotExist: # There can only be one profile!
            profile = TwitterProfile.objects.create(user=request.user, twitter_id=user_info['id'])

        return HttpResponseRedirect(_get_next(request))

    user = authenticate(twitter_id=user_info['id'])

    if user is None:
        profile = TwitterProfile(twitter_id=user_info['id'])
        user = User()
        request.session['socialregistration_profile'] = profile
        request.session['socialregistration_user'] = user
        request.session['next'] = _get_next(request)
        return HttpResponseRedirect(reverse('socialregistration_setup'))

    if not user.is_active:
        return render_to_response(
            account_inactive_template,
            extra_context,
            context_instance=RequestContext(request)
        )

    login(request, user)

    return HttpResponseRedirect(_get_next(request))

def oauth_redirect(request, consumer_key=None, secret_key=None,
    request_token_url=None, access_token_url=None, authorization_url=None,
    callback_url=None, parameters=None):
    """
    View to handle the OAuth based authentication redirect to the service provider
    """
    request.session['next'] = _get_next(request)
    client = OAuthClient(request, consumer_key, secret_key,
        request_token_url, access_token_url, authorization_url, callback_url, parameters)
    return client.get_redirect()

def oauth_callback(request, consumer_key=None, secret_key=None,
    request_token_url=None, access_token_url=None, authorization_url=None,
    callback_url=None, template='socialregistration/oauthcallback.html',
    extra_context=dict(), parameters=None):
    """
    View to handle final steps of OAuth based authentication where the user
    gets redirected back to from the service provider
    """
    client = OAuthClient(request, consumer_key, secret_key, request_token_url,
        access_token_url, authorization_url, callback_url, parameters)

    extra_context.update(dict(oauth_client=client))

    if not client.is_valid():
        return HttpResponseRedirect(reverse('login'))

    # We're redirecting to the setup view for this oauth service
    return HttpResponseRedirect(reverse(client.callback_url))

def openid_redirect(request):
    """
    Redirect the user to the openid provider
    """
    request.session['next'] = _get_next(request)
    openid_provider = request.GET.get('openid_provider', '').strip()
    request.session['openid_provider'] = openid_provider

    client = OpenID(
        request,
        'http%s://%s%s' % (
            _https(),
            Site.objects.get_current().domain,
            reverse('openid_callback')
        ),
        openid_provider
    )
    try:
        return client.get_redirect()
    except DiscoveryFailure:
        request.session['openid_error'] = True
        return HttpResponseRedirect(settings.LOGIN_URL)

def openid_callback(request, template='socialregistration/openid.html',
    extra_context=dict(), account_inactive_template='socialregistration/account_inactive.html'):
    """
    Catches the user when he's redirected back from the provider to our site
    """
    client = OpenID(
        request,
        'http%s://%s%s' % (
            _https(),
            Site.objects.get_current().domain,
            reverse('openid_callback')
        ),
        request.session.get('openid_provider')
    )

    try:
        request_args = util.normalDict(request.GET)

        if request.method == 'POST':
            request_args.update(util.normalDict(request.POST))

        if request_args:
            client.complete()
            c = client.consumer

        return_to = util.getViewURL(request, openid_callback)

        response = client.result

        ax_items = {}

        if response.status == consumer.SUCCESS:
            provider = request.session.get('openid_provider')
            # Set the schema uri depending on who the openid provier is:
            # request only name and email by default (same as Google schemas):
            schemas = GoogleOpenIDSchemas()
            if 'yahoo' in provider:
                schemas = YahooOpenIDSchemas()

            if 'myopenid' in provider:
                schemas = MyOpenIDSchemas()

            ax_response = {}
            ax_response = ax.FetchResponse.fromSuccessResponse(response)
            if ax_response:
                # Name and email schemas are always set, but not others so check if they are not empty first:
                birth_date = zip = gender = []
                if schemas.birth_date_schema:
                    birth_date = ax_response.get(schemas.birth_date_schema)
                if schemas.zip_schema:
                    zip =  ax_response.get(schemas.zip_schema)
                if schemas.gender_schema:
                    gender = ax_response.get(schemas.gender_schema)
                ax_items = {
                    'display_name': ax_response.get(schemas.name_schema),
                    'email': ax_response.get(schemas.email_schema),
                    'birth_date': birth_date,
                    'home_zip': zip,
                    'gender': gender,
                }

        request.session['ax_items'] = ax_items

    except Exception, e:
        pass


    if client.is_valid():
        identity = client.result.identity_url
        if request.user.is_authenticated():
            # Handling already logged in users just connecting their accounts
            try:
                profile = OpenIDProfile.objects.get(identity=identity)
            except OpenIDProfile.DoesNotExist: # There can only be one profile with the same identity
                profile = OpenIDProfile.objects.create(user=request.user,
                    identity=identity)

            return HttpResponseRedirect(_get_next(request))

        user = authenticate(identity=identity)
        if user is None:
            request.session['socialregistration_user'] = User()
            request.session['socialregistration_profile'] = OpenIDProfile(
                identity=identity
            )
            return HttpResponseRedirect(reverse('socialregistration_setup'))

        if not user.is_active:
            return render_to_response(
                account_inactive_template,
                extra_context,
                context_instance=RequestContext(request)
            )

        login(request, user)
        return HttpResponseRedirect(_get_next(request))

    return HttpResponseRedirect(reverse('login'))
