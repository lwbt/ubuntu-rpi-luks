#!/bin/bash

echo -e "Directory contents:\n"

ls -1 --color=always

echo -e "\nHardware:"
lscpu | grep "Model name:"
