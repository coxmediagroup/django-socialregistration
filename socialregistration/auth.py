import facebook
import urllib

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.core.urlresolvers import reverse

from socialregistration.models import (FacebookProfile, TwitterProfile, OpenIDProfile)

FACEBOOK_APP_ID = getattr(settings, 'FACEBOOK_APP_ID', '')
FACEBOOK_API_KEY = getattr(settings, 'FACEBOOK_API_KEY', '')
FACEBOOK_SECRET_KEY = getattr(settings, 'FACEBOOK_SECRET_KEY', '')

class Auth(object):
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

class FacebookAuth(Auth):
    def authenticate(self, uid=None):
        try:
            return FacebookProfile.objects.get(
                uid=uid,
                site=Site.objects.get_current()
            ).user
        except FacebookProfile.DoesNotExist:
            return None

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

class FacebookBackend:
    """ Shamlessly ripped from socialauth. 
        Class/method to authenticate users against facebook oauth2 api. """

    def authenticate(self, request, user=None):
        cookie = facebook.get_user_from_cookie(request.COOKIES, FACEBOOK_APP_ID, FACEBOOK_SECRET_KEY)

        if cookie:
            uid = cookie['uid']
            access_token = cookie['access_token']
        else:
            # if cookie does not exist
            # assume logging in normal way
            params = {}
            params["client_id"] = FACEBOOK_APP_ID
            params["client_secret"] = FACEBOOK_SECRET_KEY
            params["redirect_uri"] = reverse("facebook_oauth_login_done")[1:] 
            params["code"] = request.GET.get('code', '')

            url = "https://graph.facebook.com/oauth/access_token?"+urllib.urlencode(params)
            from cgi import parse_qs
            userdata = urllib.urlopen(url).read()
            res_parse_qs = parse_qs(userdata)
            # Could be a bot query
            if not res_parse_qs.has_key('access_token'):
                return None
                
            parse_data = res_parse_qs['access_token']
            uid = parse_data['uid'][-1]
            access_token = parse_data['access_token'][-1]
            
        try:
            fb_user = FacebookProfile.objects.get(uid=uid, site=Site.objects.get_current())
            return fb_user.user

        except FacebookProfile.DoesNotExist:
            
            return None
            '''
            # create new FacebookUserProfile
            graph = facebook.GraphAPI(access_token) 
            fb_data = graph.get_object("me")

            if not fb_data:
                return None

            username = uid
            if not user:
                user = User.objects.create(username=username)
                user.first_name = fb_data['first_name']
                user.last_name = fb_data['last_name']
                user.save()
                
            fb_profile = FacebookUserProfile(facebook_uid=uid, user=user)
            fb_profile.save()
            
            auth_meta = AuthMeta(user=user, provider='Facebook').save()
                
            return user
            '''
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except:
            return None
