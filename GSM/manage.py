#!/usr/bin/env python
import os
import sys
import shutil
import pdb

if __name__ == "__main__":
    # pdb.set_trace()
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    source_file_name = os.environ['DJANGO_ENV']
    destination_file_path = CURRENT_DIR+"/GSM/settings.py"
    source_file_path = CURRENT_DIR+"/settings/"+source_file_name+".py"
    shutil.copyfile(source_file_path,destination_file_path)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "GSM.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError:
        # The above import may fail for some other reason. Ensure that the
        # issue is really that Django is missing to avoid masking other
        # exceptions on Python 2.
        try:
            import django
        except ImportError:
            raise ImportError(
                "Couldn't import Django. Are you sure it's installed and "
                "available on your PYTHONPATH environment variable? Did you "
                "forget to activate a virtual environment?"
            )
        raise
    execute_from_command_line(sys.argv)
