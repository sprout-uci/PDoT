#!/bin/sh

ROOT_DIR=$PWD/..
EVAL_DIR=$ROOT_DIR/DoTS-experiment
BIN_DIR=$ROOT_DIR/DoTS-experiment/bin

# Create csv directory to store collected data
if [ ! -d "csv" ]; then
    cd $EVAL_DIR
    mkdir csv
fi

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
cp ../unbound-stubby-template.yml unbound-latency-cold-stubby.yml
cp ../unbound-stubby-template.yml unbound-latency-warm-stubby.yml
sed -i "s/address_data:/address_data: 127.0.0.1/" unbound-latency-cold-stubby.yml
sed -i "s/address_data:/address_data: 127.0.0.1/" unbound-latency-warm-stubby.yml
sed -i "s/idle_timeout:/idle_timeout: 0/" unbound-latency-cold-stubby.yml
sed -i "s/idle_timeout:/idle_timeout: 10000/" unbound-latency-warm-stubby.yml

# Run DoTS measurement
cd $BIN_DIR
echo "Running PDoT..."
# ./App -l > /dev/null 2>&1 &
# sleep 5
echo "Running stubby..."
echo "Running DoTS measurement (cold start)..."
for i in $(seq 0 99)
do
  cd $BIN_DIR
  sudo -b ./pdot-stubby -C pdot-latency-cold-stubby.yml -g > /dev/null 2>&1 &
  sleep 2
  cd $EVAL_DIR
  ./latency.py dots cold $i
  sudo pkill stubby
  sleep 1
done
echo "Running DoTS measurement (warm start)..."
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
echo "Cleaning up DoTS measurement..."
sudo pkill stubby
sudo pkill App
cd $BIN_DIR
sudo rm -r .libs/ # remove temporary directory used by stubby

sleep 3

# Run unbound measurement
echo "Running unbound..."
cd $BIN_DIR
./unbound -c ../unbound.conf
sleep 5
echo "Running stubby..."
echo "Running unbound measurement (cold start)..."
for i in $(seq 0 99)
do
  cd $BIN_DIR
  sudo -b ./unbound-stubby -C unbound-latency-cold-stubby.yml -g > /dev/null 2>&1 &
  sleep 1
  cd $EVAL_DIR
  ./latency.py unbound cold $i
  sudo pkill stubby
  sleep 1
done
echo "Running unbound measurement (warm start)..."
for i in $(seq 0 99)
do
  cd $BIN_DIR
  sudo -b ./unbound-stubby -C unbound-latency-warm-stubby.yml -g > /dev/null 2>&1 &
  sleep 2
  cd $EVAL_DIR
  ./latency.py unbound warm $i
  sudo pkill stubby
  sleep 1
done
echo "Cleaning up unbound measurement..."
sudo pkill stubby
sudo pkill unbound
cd $BIN_DIR
sudo rm -r .libs/ # remove temporary directory used by stubby
