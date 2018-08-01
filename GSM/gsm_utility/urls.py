from django.conf.urls import include, url
from django.contrib import admin
from .views import *

# fv = FeedbackView(mName="test")

urlpatterns = [
    # url(r'^feedback/$',fv.as_view(mName="test")),
    #url(r'^feedback/$',FeedbackView.as_view(method_name="test")),
    url(r'^feedback/$',FeedbackView.as_view()),
    url(r'^choices/$',AllChoiceView.as_view()),
    url(r'^auth/signup/$',AuthenticationView.as_view(method_name="signup")),
    url(r'^auth/login/$',AuthenticationView.as_view(method_name="login")),
    url(r'^auth/tos_update/$',AuthenticationView.as_view(method_name="tos_update")),
    url(r'^auth/rd_update/$',AuthenticationView.as_view(method_name="rd_update")),
    url(r'^auth/update/$',AuthenticationView.as_view(method_name="update")),
    url(r'^auth/deactivate/$',AuthenticationView.as_view(method_name="deactivate")),
    url(r'^auth/reactivate/$',AuthenticationView.as_view(method_name="reactivate")),
    url(r'^auth/logout/$',AuthenticationView.as_view(method_name="logout")),
    url(r'^auth/forgotpassword/$',AuthenticationView.as_view(method_name="forgot_password")),
    url(r'^auth/changepassword/$',AuthenticationView.as_view(method_name="change_password")),
    url(r'^auth/registration/verification/$',AuthenticationView.as_view(method_name="verification")),
    url(r'^auth/google/$',AuthenticationView.as_view(method_name="google_auth")),
    url(r'^auth/facebook/$',AuthenticationView.as_view(method_name="fb_auth")),
    url(r'^auth/twitter/$',AuthenticationView.as_view(method_name="twitter_auth")),
    url(r'^auth/twitter/callback/$',AuthenticationView.as_view(method_name="twitter_auth_callback")),
    url(r'^auth/linkedin/$',AuthenticationView.as_view(method_name="linkedin_auth")),
    url(r'^auth/linkedin/callback/$',AuthenticationView.as_view(method_name="linkedin_auth_callback")),
    url(r'^auth/test/$',AuthenticationView.as_view(method_name="test_method")),
    url(r'^charts/$', ATRChartView.as_view()),
    url(r'^ranking_charts/$', RankingChartView.as_view()),
]
