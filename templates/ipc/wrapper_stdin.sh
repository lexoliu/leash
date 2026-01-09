#!/bin/sh
# {{ command }} - supports stdin piping: cat file | {{ command }} "prompt"
# stdin_arg: {{ stdin_arg }}, primary_arg: {{ primary_arg }}

STDIN_CONTENT=""
if [ ! -t 0 ]; then
    STDIN_CONTENT=$(cat)
fi

if [ -n "$STDIN_CONTENT" ]; then
    if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
        exec leash-ipc {{ command }} --{{ stdin_arg }} "$STDIN_CONTENT" --{{ primary_arg }} "$*"
    else
        exec leash-ipc {{ command }} --{{ stdin_arg }} "$STDIN_CONTENT" "$@"
    fi
else
    if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
        exec leash-ipc {{ command }} --{{ primary_arg }} "$*"
    else
        exec leash-ipc {{ command }} "$@"
    fi
fi
