from django.contrib import admin
from django.urls import include, path

admin.site.site_header = "CDKCIAE administration"
admin.site.site_title = "CDKCIAE admin"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("core.urls")),
]
