#!/bin/sh
# Usage: ./generate-config.sh 55
# This will generate Stubby config files that will listen to ports 53, 54, and 55.

# Make a copy of dots-stubby.yml and use sed to replace the port number
echo "Generating config files..."
for i in $(seq 53 $1)
do
    cp ../dots-stubby.yml dots-stubby-$i.yml
    sed -i "s/53/$i/" dots-stubby-$i.yml
done
echo "Done"