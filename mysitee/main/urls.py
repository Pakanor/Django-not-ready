from django.urls import path
from . import views
from .views import get_Task, edit_Task, task_delete, create_User, login_user, activate_user, home, logout_user
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('task/show/<int:user_id>', get_Task, name="task_show"),
    path('home/<int:task_id>/edit', edit_Task, name="task_edit"),
    path('task/<int:task_id>/delete', task_delete, name="task_delete"),
    path('register', create_User, name='user_creation'),
    path('login', login_user, name='user_login'),
    path('activate/<str:token>/', activate_user, name='user_activate'),
    path('home', home, name='home'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout', logout_user, name='logout'),







]
