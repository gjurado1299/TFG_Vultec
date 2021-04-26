from django.db import models

class VulnerabilityManager(models.Manager):
    def preferred_order(self, *args, **kwargs):
        """Sort patterns by preferred order of Y then -- then N"""
        qs = self.get_queryset().filter(*args, **kwargs)
        qs = qs.annotate( custom_order=
            models.Case( 
                models.When(risk_level='low', then=models.Value(0)),
                models.When(risk_level='info', then=models.Value(1)),
                models.When(risk_level='medium', then=models.Value(2)),
                default=models.Value(3),
                output_field=models.IntegerField(),)
            ).order_by('custom_order')
        return qs