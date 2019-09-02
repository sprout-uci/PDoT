#!/bin/sh
# Usage: ./generate-config.sh 55
# This will generate Stubby config files that will listen to ports 53, 54, and 55.

# Make a copy of normal-stubby.yml and use sed to replace the port number
echo "Generating config files..."
for i in $(seq 53 $1)
do
    cp ../normal-stubby.yml normal-stubby-$i.yml
    sed -i "s/53/$i/" normal-stubby-$i.yml
done
echo "Done"
