from rest_framework import serializers
from .models import *

class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = '__all__'


class ByteBridgesSerializer(serializers.ModelSerializer):
    class Meta:
        model = ByteBridges
        fields = '__all__'