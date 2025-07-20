from django.urls import include, path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'admin/blogs', views.AdminBlogViewSet, basename='admin-blogs')
router.register(r'blogs', views.PublicBlogViewSet, basename='public-blogs')

urlpatterns = [
    # ================ Admin/Parent AUTHENTICATION ================
    path('auth/parent/signup/', views.parent_signup, name='parent-signup'),
    path('verify-email/<uuid:token>/', views.verify_email, name='verify_email'),
    path('resend-verification/', views.resend_verification_email, name='resend_verification'),
    path('auth/login/', views.user_login, name='user-login'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('auth/profile/', views.user_profile, name='user-profile'),
    path('admin/profile/update/', views.admin_profile_update, name='admin-profile-update'),
    path('admin/profile/image/', views.profile_image_upload, name='profile-image-upload'),
    
    # ================ USER LISTS ADMIN ONLY APIS ================
    path('admin/users/subadmins/', views.subadmin_list, name='subadmin-list'),
    path('admin/users/clinics/', views.clinic_list, name='clinic-list'),
    path('admin/users/parents/', views.parent_list, name='parent-list'),
    path('admin/profile/update/', views.admin_profile_update, name='admin-profile-update'),
    path('admin/profile/image/', views.profile_image_upload, name='profile-image-upload'),
    
    # ================ SUBADMIN MANAGEMENT (CRUD) ADMIN ONLY APIS ================
    path('admin/subadmin/create/', views.create_subadmin, name='create-subadmin'),  # existing
    path('subadmin/<uuid:subadmin_id>/permissions/', views.get_subadmin_permissions, name='get_subadmin_permissions'),
    path('subadmin/<uuid:subadmin_id>/permissions/update/', views.update_subadmin_permissions, name='update_subadmin_permissions'),
    path('admin/subadmin/<uuid:user_id>/', views.subadmin_detail, name='subadmin-detail'),
    path('admin/subadmin/<uuid:user_id>/update/', views.subadmin_update, name='subadmin-update'),
    path('admin/subadmin/<uuid:user_id>/delete/', views.subadmin_delete, name='subadmin-delete'),
    
    # ================ CLINIC MANAGEMENT (CRUD) ADMIN ONLY APIS ================
    path('admin/clinic/create/', views.create_clinic, name='create-clinic'),  # existing
    path('admin/clinic/<uuid:user_id>/', views.clinic_detail, name='clinic-detail'),
    path('admin/clinic/<uuid:user_id>/update/', views.clinic_update, name='clinic-update'),
    path('admin/clinic/<uuid:user_id>/delete/', views.clinic_delete, name='clinic-delete'),
    
    # ================ PARENT MANAGEMENT (RUD only) PARENT AND ADMIN ONLY APIS ================
    path('admin/parent/<uuid:user_id>/', views.parent_detail, name='parent-detail'),
    path('admin/parent/<uuid:user_id>/update/', views.parent_update, name='parent-update'),
    path('admin/parent/<uuid:user_id>/delete/', views.parent_delete, name='parent-delete'),

    # ================ SUBSCRIPTION MANAGEMENT (ADMIN/SUBADMIN ONLY) ================
    # Subscription Plan Management
    path('admin/subscription/plans/', views.SubscriptionPlanViewSet.as_view({'get': 'list', 'post': 'create'}), name='subscription-plans-list'),
    path('admin/subscription/plans/<uuid:pk>/', views.SubscriptionPlanViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='subscription-plans-detail'),
    path('admin/subscription/plans/<uuid:pk>/toggle-status/', views.SubscriptionPlanViewSet.as_view({'post': 'toggle_status'}), name='subscription-plans-toggle-status'),
    path('admin/subscription/billing-cycles/', views.SubscriptionPlanViewSet.as_view({'get': 'billing_cycles'}), name='subscription-billing-cycles'),
    
    # User Subscription Management
    path('admin/subscription/subscriptions/', views.UserSubscriptionViewSet.as_view({'get': 'list', 'post': 'create'}), name='user-subscriptions-list'),
    path('admin/subscription/subscriptions/<uuid:pk>/', views.UserSubscriptionViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='user-subscriptions-detail'),
    path('admin/subscription/subscriptions/<uuid:pk>/update-status/', views.UserSubscriptionViewSet.as_view({'patch': 'update_status'}), name='user-subscriptions-update-status'),
    path('admin/subscription/subscriptions/<uuid:pk>/activate/', views.UserSubscriptionViewSet.as_view({'post': 'activate'}), name='user-subscriptions-activate'),
    path('admin/subscription/subscriptions/<uuid:pk>/cancel/', views.UserSubscriptionViewSet.as_view({'post': 'cancel'}), name='user-subscriptions-cancel'),
    path('admin/subscription/subscriptions/<uuid:pk>/renew/', views.UserSubscriptionViewSet.as_view({'post': 'renew'}), name='user-subscriptions-renew'),
    path('admin/subscription/stats/', views.UserSubscriptionViewSet.as_view({'get': 'subscription_stats'}), name='subscription-stats'),

    # ======================= STRIPE PAYMENT URLS =======================
    path('payments/create-checkout-session/', views.create_checkout_session, name='create-checkout-session'),
    path('payments/create-customer-portal-session/', views.create_customer_portal_session, name='create-customer-portal-session'),
    path('payments/stripe-webhook/', views.stripe_webhook, name='stripe-webhook'), # This URL needs to be added to your Stripe dashboard
    path('payment-success/', views.payment_success, name='payment_success'),
    path('payment-cancelled/', views.payment_cancelled, name='payment_cancelled'),

    # Public endpoint to get list of clinics for appointment booking
    path('clinics/list/', views.clinic_list_for_appointments, name='clinic_list_for_appointments'),
    
    # ====================== APPOINTMENT MANAGEMENT (ADMIN/SUBADMIN) ======================
    path('admin/appointments/', views.appointment_list, name='appointment_list'),
    path('appointments/my-appointments/', views.parent_appointments_list, name='parent_appointments_list'),
    path('appointments/stats/', views.parent_appointment_stats, name='parent_appointments_stats'),
    path('admin/appointments/<uuid:appointment_id>/', views.appointment_detail, name='appointment_detail'),
    path('admin/appointments/<uuid:appointment_id>/update/', views.appointment_update, name='appointment_update'),
    path('admin/appointments/<uuid:appointment_id>/delete/', views.appointment_delete, name='appointment_delete'),
    path('appointments/create/', views.create_appointment, name='create_appointment'),
    
    # ====================== MEETING MANAGEMENT (ADMIN/SUBADMIN) ======================
    # Meeting creation and management
    path('admin/meetings/create/', views.create_meeting, name='create_meeting'),
    path('admin/meetings/create-instant/', views.create_instant_meeting, name='create_instant_meeting'),
    path('admin/meetings/', views.meeting_list, name='meeting_list'),
    path('admin/meetings/<uuid:meeting_id>/', views.meeting_detail, name='meeting_detail'),
    path('admin/meetings/<uuid:meeting_id>/update/', views.meeting_update, name='meeting_update'),
    path('clinic/donor-stats/', views.clinic_donor_booking_stats, name='clinic_donor_stats'),
    
    
    # Meeting status management
    path('admin/meetings/<uuid:meeting_id>/status/<str:new_status>/', views.meeting_status_update, name='meeting_status_update'),
    path('admin/meetings/<uuid:meeting_id>/send-reminders/', views.send_meeting_reminders, name='send_meeting_reminders'),
    
    # ====================== DASHBOARD STATISTICS ======================
    path('admin/dashboard/stats/', views.dashboard_stats, name='dashboard_stats'),

    # ================ AUTHENTICATION AND PASSWORD MANAGEMENT ================
    path("auth/forgot-password/", views.forgot_password_email, name="forgot-password-email"),
    path("auth/verify-otp/",     views.verify_otp,           name="verify-otp"),
    path("auth/reset-password/", views.reset_password,       name="reset-password"),
    path('auth/change-password/', views.change_password, name='change-password'),

    ###################################### Donor Management ######################################
    path('donors/', views.DonorViewSet.as_view({'get': 'list', 'post': 'create'}), name='donor-list-create'),
    # Handles retrieve (GET), update (PUT/PATCH), and delete (DELETE) for a single donor
    path('clinic/donors/<str:donor_id>/', views.DonorViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='donor-detail-update-delete'),
    path('donors/import/', views.import_donors_view, name='donor-import'),
    path('donors/find-matches/', views.find_matching_donors_view, name='donor-find-matches'),
    path('donors/template/download/', views.download_donor_template, name='download_donor_template'),
    path('donors/import/preview/', views.preview_donor_import, name='preview_donor_import'),
    path('donors/bulk-delete/', views.bulk_delete_donors, name='bulk_delete_donors'),
    path('donors/statistics/', views.donor_statistics, name='donor_statistics'),

    # Fertility Profile URLs
    path('fertility-profile/create/', views.create_fertility_profile, name='create_fertility_profile'),
    path('fertility-profile/<str:donor_type_preference>/update/', views.update_fertility_profile, name='update_fertility_profile'),
    path('fertility-profile/list/', views.get_fertility_profiles, name='get_fertility_profiles'),
    
    # path('donors/trigger-embedding/', views.trigger_donor_embedding_on_create, name='trigger_donor_embedding'),
    path('contact-us/', views.contact_us_view, name='contact-us'),
    path('', include(router.urls))
]