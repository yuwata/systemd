#!/bin/bash

set -eu
set -o pipefail

stat_contributor() {
    local version=${1?}
    local total=${2?}
    local rank=${3?}

    local line=$(git shortlog -s -n --no-merges v"$((version-1))"..v"$((version))" | head -n "$rank" | tail -n 1)
    local num=$(echo "$line" | awk '{ print $1 }')
    local author=$(echo "$line" | sed -e 's/^[[:space:]]*[0-9]*[[:space:]]*//')
    local percent=$(echo "scale=2;$num*100/$total" | bc -l)

    echo -n " | $author (${num} commits, $percent%)"
}

stat_version() {
    local version=${1?}

    local total=$(git log --oneline --no-merges v"$((version-1))"..v"$((version))" | wc -l)

    echo -n "| v$version | $total"

    for ((j=1;j<=4;j++)); do
        stat_contributor "$version" "$total" "$j"
    done

    echo " |"
}

stat_header() {
    echo "| version | commits | author_1 | author_2 | author_3 | author_4 |"
    echo "| ------- | ------- | -------- | -------- | -------- | -------- |"
}

stat() {
    stat_header
    for ((i=252;i>=200;i--)); do
        stat_version "$i"
    done
}

stat
