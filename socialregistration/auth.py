import facebook
import urllib
import logging

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.core.urlresolvers import reverse
from django.utils import simplejson

from socialregistration.models import (FacebookProfile, TwitterProfile, OpenIDProfile)

FACEBOOK_APP_ID = getattr(settings, 'FACEBOOK_APP_ID', '')
FACEBOOK_API_KEY = getattr(settings, 'FACEBOOK_API_KEY', '')
FACEBOOK_SECRET_KEY = getattr(settings, 'FACEBOOK_SECRET_KEY', '')
logger = logging.getLogger(__name__)

class Auth(object):
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

#class FacebookAuth(Auth):
#    def authenticate(self, uid=None):
#        try:
#            return FacebookProfile.objects.get(
#                uid=uid,
#                site=Site.objects.get_current()
#            ).user
#        except FacebookProfile.DoesNotExist:
#            return None

class TwitterAuth(Auth):
    def authenticate(self, twitter_id=None):
        try:
            return TwitterProfile.objects.get(
                twitter_id=twitter_id,
                site=Site.objects.get_current()
            ).user
        except TwitterProfile.DoesNotExist:
            return None

class OpenIDAuth(Auth):
    def authenticate(self, identity=None):
        try:
            return OpenIDProfile.objects.get(
                identity=identity,
                site=Site.objects.get_current()
            ).user
        except OpenIDProfile.DoesNotExist:
            return None

class FacebookBackend(Auth):
    """ Shamlessly ripped from socialauth. 
        Class/method to authenticate users against facebook oauth2 api. """

    def get_access_token(self, code, redirect_uri):
        """ Retrieve the access_token from fb oauth 
            TODO: implement in helpers and migrate
            standalone implementations.
        """
        params = {}
        params["client_id"] = FACEBOOK_APP_ID
        params["client_secret"] = FACEBOOK_SECRET_KEY
        params["redirect_uri"] = redirect_uri
        params["code"] = code
        
        url = "https://graph.facebook.com/oauth/access_token?"+urllib.urlencode(params)
        from cgi import parse_qs
        userdata = urllib.urlopen(url).read()
        resp_dict = parse_qs(userdata)
        logger.debug("response dictionary is %s" % resp_dict)
        if not 'access_token' in resp_dict.keys():
            return None 
        elif "error" in resp_dict.keys():
            return resp_dict["error"]
        else:
            return resp_dict["access_token"][-1]
    
    def get_user_data(self, token):
        """ 
        Retrieve information about the user from facebook 
        """
        params = {"access_token" : token}
        url = 'https://graph.facebook.com/me?' + urllib.urlencode(params)
        user_data = simplejson.load(urllib.urlopen(url))
        logger.debug("user_data is %s" % user_data)         
        return user_data

    def authenticate(self, request, user=None):
        logger.debug("In authenticate")
        cookie = facebook.get_user_from_cookie(request.COOKIES, FACEBOOK_APP_ID, FACEBOOK_SECRET_KEY)

        if cookie:
            access_token = cookie['access_token']
        else:
            # if cookie does not exist
            # assume logging in normal way
            redir_uri = request.build_absolute_uri(reverse("facebook_oauth_login_done"))
            
            # As far as I can tell this code never expires
            # Try retrieving the code from teh session but if we've 
            # hit the standard login process for the first time
            # retrieve the code from get params and store it in the session.
            # this is mostly for the registration process where authenticate
            # is called (through the model...) without the prelim facebook_oauth_login call which
            # is where the code is included into the GET params
            if "facebook_code" in request.session.keys():
                code = request.session["facebook_code"] 
            else:
                code = request.GET.get('code', '')
                if code:
                    request.session["facebook_code"] = code
            access_token = self.get_access_token(code, redir_uri)

        # Use the access_token to get supporting
        # information about the user.
        if access_token:
            request.session["facebook_access_token"] = access_token
            user_data = self.get_user_data(access_token)       
            logger.debug("user_data is  %s" % user_data)
            uid = user_data["id"]
        else:
            return None

        try:
            fb_user = FacebookProfile.objects.get(uid=uid, site=Site.objects.get_current())
            return fb_user.user

        except FacebookProfile.DoesNotExist:
            # Facebook authentication passed but this 
            # FacebookProfile + Site doesn't exist, so
            # create it.
            logger.debug("Auth DoesNotExist\n")
            user = User()
            fb_profile = FacebookProfile(user=user, uid=uid)
            request.session['socialregistration_user'] = user
            request.session['socialregistration_profile'] = fb_profile
            return user
