from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_overview, name='index'),    
    path('register/', views.register, name='register'),
    path('login_user', views.login_user, name='login_user'),
    path('logout_user', views.logout_user, name='logout_user'),
    path('dashboard-accounts/', views.dashboard_accounts, name='dashboard_accounts'),
    path('dashboard-purchase/', views.dashboard_purchase, name='dashboard_purchase'),
    path('dashboard-next-phase/', views.dashboard_next_phase, name='dashboard_next_phase'),
    path('dashboard-rules/', views.dashboard_rules, name='dashboard_rules'),
    path('dashboard-referral/', views.dashboard_referral, name='dashboard_referral'),
    path('dashboard-payouts/', views.dashboard_payouts, name='dashboard_payouts'),
    path('dashboard-transactions/', views.dashboard_transactions, name='dashboard_transactions'),
    path('dashboard-certificates/', views.dashboard_certificates, name='dashboard_certificates'),
    path('verify_payment', views.verify_payment, name='verify_payment'),
    path('process_purchase/', views.process_purchase, name='process_purchase'),
    path('payment/callback/', views.payment_callback, name='payment_callback'),
]