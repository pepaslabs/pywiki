#!/bin/bash

set -e
set -o pipefail
set -x

for i in wiki wiki2 wiki3
do
    cp -a code.py /var/www/${i}/
    cp -a pam_authenticate.py /var/www/${i}/

    rm -rf /var/www/${i}/static
    cp -a static /var/www/${i}/

    rm -rf /var/www/${i}/templates
    cp -a templates /var/www/${i}/
done
