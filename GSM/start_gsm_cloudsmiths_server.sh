#!/bin/bash
# sudo supervisorctl restart greenpeace
NAME="GSM" # Name of the django project
DJANGODIR=/home/ubuntu/mtsp_backend/GSM # Django project directory
SOCKFILE=/home/ubuntu/mtsp_backend/GSM/run/gunicorn.sock # we will communicte using this unix socket
USER=ubuntu # the user to run as
#GROUP=webapps # the group to run as
NUM_WORKERS=3 # how many worker processes should Gunicorn spawn
PENDING_CONNECTIONS=2048
NUM_THREADS=8
DJANGO_SETTINGS_MODULE=${NAME}.settings # which settings file should Django use
DJANGO_WSGI_MODULE=${NAME}.wsgi # WSGI module name
echo "Starting $NAME as `whoami`"
# Activate the virtual environment
cd $DJANGODIR
source ~/GSM_Cloudsmiths/bin/activate
export DJANGO_SETTINGS_MODULE=$DJANGO_SETTINGS_MODULE
export DJANGO_WSGI_MODULE=$DJANGO_WSGI_MODULE
export PYTHONPATH=$DJANGODIR:$PYTHONPATH
# Create the run directory if it doesn't exist
RUNDIR=$(dirname $SOCKFILE)
test -d $RUNDIR || mkdir -p $RUNDIR
# Start your Django Unicorn
# Programs meant to be run under supervisor should not daemonize themselves (do not use --daemon)
exec ~/GSM_Cloudsmiths/bin/gunicorn ${DJANGO_WSGI_MODULE}:application \
--name $NAME \
--workers $NUM_WORKERS \
--threads $NUM_THREADS \
--backlog $PENDING_CONNECTIONS \
--user=$USER  \
--bind=unix:$SOCKFILE \
--timeout 90 \
--log-level=debug \
--log-file=/home/ubuntu/log/gunicorn.log
# sudo service nginx restart
