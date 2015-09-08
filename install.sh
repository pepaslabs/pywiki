#!/bin/bash

set -e
set -o pipefail
set -x

for i in wiki
do
    cp -a code.py ~/www/${i}/

    rm -rf ~/www/${i}/static
    cp -a static ~/www/${i}/

    rm -rf ~/www/${i}/templates
    cp -a templates ~/www/${i}/
done
