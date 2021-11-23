#!/bin/bash

echo "copying shared objects..."

sudo cp Debug/libzkinject.so /usr/lib/
sudo cp Debug/libzkinject.so.1 /usr/lib/
sudo cp Debug/libzkinject.so.0.1 /usr/lib/

echo "copying header files..."

sudo cp include/* /usr/include/zkinject/
