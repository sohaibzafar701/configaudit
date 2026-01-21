"""
Custom QuerySet managers for organization filtering
"""
from django.db import models


class OrganizationQuerySet(models.QuerySet):
    """QuerySet that automatically filters by organization"""
    
    def filter_by_org(self, organization):
        """Filter by organization"""
        if organization is None:
            return self.none()
        return self.filter(organization=organization)
    
    def for_user(self, user):
        """Filter for a specific user's organization"""
        if not user.is_authenticated:
            return self.none()
        
        try:
            profile = user.userprofile
            if profile.is_super_admin():
                # Super Admin can see aggregated data but not individual records
                # Return empty queryset for individual data access
                return self.none()
            else:
                return self.filter(organization=profile.organization)
        except AttributeError:
            return self.none()


class OrganizationManager(models.Manager):
    """Manager for models with organization filtering"""
    
    def get_queryset(self):
        """Return QuerySet with organization filtering"""
        return OrganizationQuerySet(self.model, using=self._db)
    
    def filter_by_org(self, organization):
        """Filter by organization"""
        return self.get_queryset().filter_by_org(organization)
    
    def for_user(self, user):
        """Filter for a specific user's organization"""
        return self.get_queryset().for_user(user)
    
    def platform_rules(self):
        """Get only platform rules (for Rule model)"""
        return self.get_queryset().filter(organization__isnull=True)
