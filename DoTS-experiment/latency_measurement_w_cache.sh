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
cp ../pdot-stubby-template.yml pdot-latency-cold-stubby.yml
cp ../pdot-stubby-template.yml pdot-latency-warm-stubby.yml
sed -i "s/address_data:/address_data: 127.0.0.1/" pdot-latency-cold-stubby.yml
sed -i "s/address_data:/address_data: 127.0.0.1/" pdot-latency-warm-stubby.yml
sed -i "s/idle_timeout:/idle_timeout: 0/" pdot-latency-cold-stubby.yml
sed -i "s/idle_timeout:/idle_timeout: 10000/" pdot-latency-warm-stubby.yml

# Run PDoT
cd $BIN_DIR
echo "Running PDoT..."
./App -l > /dev/null 2>&1 &
sleep 20

# Run stubby for pre-population
cd $BIN_DIR
sudo -b ./pdot-stubby -C pdot-latency-warm-stubby.yml -g > /dev/null 2>&1 &
sleep 1

# Run dig command to pre-populate cache
dig @127.0.0.1 google.com      +noall +answer +timeout=10
sleep 1
dig @127.0.0.1 facebook.com    +noall +answer +timeout=10
sleep 1
dig @127.0.0.1 youtube.com     +noall +answer +timeout=10
sleep 1
dig @127.0.0.1 twitter.com     +noall +answer +timeout=10
sleep 1
dig @127.0.0.1 microsoft.com   +noall +answer +timeout=10
sleep 1
dig @127.0.0.1 linkedin.com    +noall +answer +timeout=10
sleep 1
dig @127.0.0.1 wikipedia.org   +noall +answer +timeout=10
sleep 1
dig @127.0.0.1 plus.google.com +noall +answer +timeout=10
sleep 1
dig @127.0.0.1 instagram.com   +noall +answer +timeout=10
sleep 1
dig @127.0.0.1 apple.com       +noall +answer +timeout=10
sleep 1

# Cleanup
sudo pkill stubby
sleep 1

# Run cold start measurement with cache
echo "Running DoTS measurement (cold start) with cache..."
for i in $(seq 0 99)
do
  cd $BIN_DIR
  sudo -b ./pdot-stubby -C pdot-latency-cold-stubby.yml -g > /dev/null 2>&1 &
  sleep 1
  cd $EVAL_DIR
  ./latency.py dots cold $i
  sudo pkill stubby
  sleep 1
done
# Change csv file name
cd $CSV_DIR
mv dns_query_time_dots_cold.csv dns_query_time_dots_cold_w_cache.csv

# Run warm start measurement with cache
echo "Running DoTS measurement (warm start) with cache..."
for i in $(seq 0 99)
do
  cd $BIN_DIR
  sudo -b ./pdot-stubby -C pdot-latency-warm-stubby.yml -g > /dev/null 2>&1 &
  sleep 2
  cd $EVAL_DIR
  ./latency.py dots warm $i
  sudo pkill stubby
  sleep 1
done
# Change csv file name
cd $CSV_DIR
mv dns_query_time_dots_warm.csv dns_query_time_dots_warm_w_cache.csv

# Clean up
echo "Cleaning up DoTS measurement..."
sudo pkill stubby
sudo pkill App
cd $BIN_DIR
sudo rm -r .libs/ # remove temporary directory used by stubby
