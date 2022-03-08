#!/bin/bash

if [[ $# -eq 0 ]]
then
    DIR="Debug"
else
    if [[ -z $1 ]]
    then
        DIR="Debug"
    else
        DIR=$1
    fi
fi

echo "copying shared objects from ${DIR}"

sudo cp ${DIR}/libzkinject.so /usr/lib/
sudo cp ${DIR}/libzkinject.so.1 /usr/lib/
sudo cp ${DIR}/libzkinject.so.0.1 /usr/lib/

echo "copying header files from include"

sudo cp include/* /usr/include/zkinject/
