from django.db import models
from django.db import connections
from django.contrib.auth.models import User


class Task(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.CharField(max_length=255,null=True,blank=True)
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    due_date = models.DateTimeField(null=True,blank=True)

    def __str__(self):
        return self.title
