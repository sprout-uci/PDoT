#!/bin/sh

# Run DoTS measurement
echo "Running stubby..."
cd ~/DoTS-experiment
echo "Running DoTS measurement (cold start)..."
for i in $(seq 0 999)
do
  sudo -b stubby -C dots-stubby.yml -g > /dev/null 2>&1 &
  sleep 2
  ./latency.py dots cold $i
  sudo pkill stubby
  sleep 1
done
echo "Running DoTS measurement (warm start)..."
for i in $(seq 0 99)
do
  sudo -b stubby -C dots-stubby.yml -g > /dev/null 2>&1 &
  sleep 2
  ./latency.py dots warm $i
  sudo pkill stubby
  sleep 1
done
echo "Cleaning up DoTS measurement..."
sudo pkill stubby
sudo pkill App

sleep 3

# Run unbound measurement
echo "Running unbound..."
unbound -c ~/DoTS-experiment/unbound.conf
sleep 3
echo "Running stubby..."
cd ~/DoTS-experiment
echo "Running unbound measurement (cold start)..."
for i in $(seq 0 999)
do
  cd ~/getdns/build/src
  sudo -b ./stubby -C ~/DoTS-experiment/normal-stubby.yml -g > /dev/null 2>&1 &
  sleep 2
  cd ~/DoTS-experiment
  ./latency.py unbound cold $i
  sudo pkill stubby
  sleep 1
done
echo "Running unbound measurement (warm start)..."
for i in $(seq 0 99)
do
  cd ~/getdns/build/src
  sudo -b ./stubby -C ~/DoTS-experiment/normal-stubby.yml -g > /dev/null 2>&1 &
  sleep 2
  cd ~/DoTS-experiment
  ./latency.py unbound warm $i
  sudo pkill stubby
  sleep 1
done
echo "Cleaning up unbound measurement..."
sudo pkill stubby
sudo pkill unbound
