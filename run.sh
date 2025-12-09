#!/bin/sh

PID="$1"

EVENT="cycles"

perf stat -d -p "$PID" sleep 10 & asprof --total -e "$EVENT" -t -f with_perf_2.html -d 10 "$PID" & wait
