#!/bin/bash


### Prepare twig
make

rm twig.o

### Run twig to read
# Check if a "-d" argument was passed
if [ "$1" ]; then
    echo ""
    echo "Running twig with desired flag on 172.31.128.0_24.dmp"
    echo ""
    ./twig $1 tools/172.31.128.0_24.dmp
else
    # Default behavior
    echo ""
    echo "Running twig on 172.31.128.0_24.dmp"
    echo ""
    ./twig tools/172.31.128.0_24.dmp
fi

# Clean up after ourselves
rm twig