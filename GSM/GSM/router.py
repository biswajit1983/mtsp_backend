# -*- coding: utf-8 -*-
class UtilityRouter:
    """
    A router to control all database operations on models in the
    gsm_user application.
    """
    def db_for_read(self, model, **hints):
        """
        Attempts to read gsm_user models go to gsm_user.
        """
        if model._meta.app_label == 'utility':
            return 'utility'
        return None

    def db_for_write(self, model, **hints):
        """
        Attempts to write gsm_user models go to gsm_user.
        """
        if model._meta.app_label == 'utility':
            return 'utility'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        """
        Allow relations if a model in the gsm_user app is involved.
        """
        if obj1._meta.app_label == 'utility' or \
           obj2._meta.app_label == 'utility':
           return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Make sure the gsm_user app only appears in the 'gsm_user'
        database.
        """
        if app_label == 'utility':
            return db == 'utility'
        return None
