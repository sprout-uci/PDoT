#!/bin/sh

ROOT_DIR=$PWD/..
EVAL_DIR=$ROOT_DIR/DoTS-experiment
BIN_DIR=$ROOT_DIR/DoTS-experiment/bin

# Create csv directory to store collected data
if [ ! -d "csv" ]; then
    cd $EVAL_DIR
    mkdir csv
fi
CSV_DIR=$ROOT_DIR/DoTS-experiment/csv

# Create images directory to store plots
if [ ! -d "images" ]; then
    cd $EVAL_DIR
    mkdir images
fi

# Copy Stubby config files to bin directory
cd $BIN_DIR
echo "Copy paste the IP address of the VM running PDoT here:"
read PDOT_ADDRESS
cp ../pdot-stubby-template.yml pdot-latency-stubby.yml
sed -i "s/address_data:/address_data: $PDOT_ADDRESS/" pdot-latency-stubby.yml
cp ../cloudflare-stubby-template.yml cloudflare-latency-stubby.yml

# Run PDoT measurement
cd $BIN_DIR
echo "Running stubby..."
echo "Running PDoT measurement (cold start)..."
for i in $(seq 0 999)
do
  cd $BIN_DIR
  sudo -b ./pdot-stubby -C pdot-latency-stubby.yml -g > /dev/null 2>&1 &
  sleep 1
  cd $EVAL_DIR
  ./latency.py pdot cold $i
  sudo pkill stubby
  sleep 1
done
cd $CSV_DIR
mv dns_query_time_pdot_cold.csv dns_query_time_pdot_cold_real_world.csv
echo "Running PDoT measurement (warm start)..."
for i in $(seq 0 99)
do
  cd $BIN_DIR
  sudo -b ./pdot-stubby -C pdot-latency-stubby.yml -g > /dev/null 2>&1 &
  sleep 2
  cd $EVAL_DIR
  ./latency.py pdot warm $i
  sudo pkill stubby
  sleep 1
done
cd $CSV_DIR
mv dns_query_time_pdot_warm.csv dns_query_time_pdot_warm_real_world.csv
echo "Cleaning up PDoT measurement..."
sudo pkill stubby
sudo pkill App
cd $BIN_DIR
sudo rm -r .libs/ # remove temporary directory used by stubby
 
# sleep 3

# # Run cloudflare measurement
# echo "Running stubby..."
# echo "Running cloudflare measurement (cold start)..."
# for i in $(seq 0 999)
# do
#   cd $BIN_DIR
#   sudo -b ./cloudflare-stubby -C cloudflare-latency-stubby.yml -g > /dev/null 2>&1 &
#   sleep 1
#   cd $EVAL_DIR
#   ./latency.py cloudflare cold $i
#   sudo pkill stubby
#   sleep 1
# done
# cd $CSV_DIR
# mv dns_query_time_cloudflare_cold.csv dns_query_time_cloudflare_cold_real_world.csv
# echo "Running cloudflare measurement (warm start)..."
# for i in $(seq 0 99)
# do
#   cd $BIN_DIR
#   sudo -b ./cloudflare-stubby -C cloudflare-latency-stubby.yml -g > /dev/null 2>&1 &
#   sleep 2
#   cd $EVAL_DIR
#   ./latency.py cloudflare warm $i
#   sudo pkill stubby
#   sleep 1
# done
# cd $CSV_DIR
# mv dns_query_time_cloudflare_warm.csv dns_query_time_cloudflare_warm_real_world.csv
# echo "Cleaning up cloudflare measurement..."
# sudo pkill stubby
# cd $BIN_DIR
# sudo rm -r .libs/ # remove temporary directory used by stubby
