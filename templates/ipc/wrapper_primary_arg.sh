#!/bin/sh
# {{ command }} <value> -> leash-ipc {{ command }} --{{ primary_arg }} "<value>"
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
    exec leash-ipc {{ command }} --{{ primary_arg }} "$*"
else
    exec leash-ipc {{ command }} "$@"
fi