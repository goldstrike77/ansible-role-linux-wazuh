#!/bin/bash

# Wazuh script to generate a Vulnerability Detector's feed for Red Hat systems
# Copyright (C) 2015-2020, Wazuh Inc.
# May 9, 2018.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

page=1
last_page=0
directory=$1
year=${2:-2010}

if [ $# -le 0 ]
then
    echo "Usage: $0 <dest_path> [Optional: <year_since>]"
    exit 1
fi

if [[ ! -d $directory ]]
then
    echo "Invalid destination path: '$directory'. It must be a directory."
    exit 1
fi

if [ $year -le 1998 ]
then
    echo "Year must be greater or equal than 1999"
    year=1999
fi

while [ true ]
do
    link="https://access.redhat.com/labs/securitydataapi/cve.json?after=$year-01-01&per_page=1000&page=$page"
    file=$directory/redhat-feed$page.json
    if [ $last_page -ne $page ]
    then
        echo "Fetching $link"
    fi

    last_page=$page
    result=$(curl -O assets/content.json $link --output $file --silent -w '%{http_code}')

    if [ $result -ne 200 ]
    then
        echo "Page download failed ($result), retrying..."
        rm -f $file
        continue
    fi

    content=`cat $file`
    if [[ $content == "[]" ]]
    then
        rm -f $file
        break
    fi

    page=$[ $page + 1 ]
done

exit 0
