#!/bin/sh
# Usage: ./generate-config.sh 55
# This will generate Stubby config files that will listen to ports 53, 54, and 55.

# Make a copy of dots-stubby.yml and use sed to replace the port number
echo "Generating config files..."
echo "Provide IP address of machine that is running PDoT:"
read IP_ADDR
for i in $(seq 53 $1)
do
    cp ../pdot-stubby-template.yml pdot-stubby-$i.yml
    sed -i "s/53/$i/" pdot-stubby-$i.yml
    sed -i "s/address_data:/address_data: $IP_ADDR/" pdot-stubby-$i.yml
done
echo "Done"