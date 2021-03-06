#!/bin/sh
# Usage: ./dots_parallel_measurement.sh 55
# This will generate Stubby instances that will listen to ports 53, 54, and 55.

START_PORT=53

ROOT_DIR=$PWD/..
EVAL_DIR=$ROOT_DIR/DoTS-experiment
PDOT_STUBBY_DIR=$ROOT_DIR/getdns-with-ratls/build/src

option="${1}"
case ${option} in
  "one") # ./dots_rate_measurement.sh one 53 100
    END_PORT=$2
    echo "Running experiment for one time..."
    #echo "Running stubby..."
    cd $PDOT_STUBBY_DIR
    for i in $(seq $START_PORT $END_PORT)
    do
      #echo "Running stubby with dots-stubby-$i.yml"
      nohup sudo -b ./stubby -C $EVAL_DIR/dots-config/pdot-stubby-${i}.yml > /dev/null 2>&1 &
      sleep 1 
    done
    sleep 3 
    #echo "Running DoTS measurement..."
    cd $EVAL_DIR
    seq $START_PORT $END_PORT | parallel -j $(($END_PORT-$START_PORT+1)) ./throughput.py dots {} $3 $(($END_PORT-$START_PORT+1))
    #echo "Cleaning up DoTS measurement..."
    sleep 5 
    sudo pkill stubby
    ;;
  "full_client") # ./dots_rate_measurement.sh full_client 100
    echo "Running full client experiment..."
    for END_PORT in 53 54 56 57 62 72 77 102
    do
      echo "Experiment for $(($END_PORT-$START_PORT+1)) clients:"
      #echo "Running stubby..."
      cd $PDOT_STUBBY_DIR
      for i in $(seq $START_PORT $END_PORT)
      do
        #echo "Running stubby with dots-stubby-$i.yml"
        nohup sudo -b ./stubby -C $EVAL_DIR/dots-config/pdot-stubby-${i}.yml > /dev/null 2>&1 &
        sleep 1 
      done
      sleep 3 
      #echo "Running DoTS measurement..."
      cd $EVAL_DIR
      seq $START_PORT $END_PORT | parallel -j $(($END_PORT-$START_PORT+1)) ./throughput.py dots {} $2 $(($END_PORT-$START_PORT+1))
      #echo "Cleaning up DoTS measurement..."
      sleep 5 
      sudo pkill stubby
      sleep 10 
    done
    ;;
  "full_rate") # ./dots_rate_measurement.sh full_rate 53
    echo "Running full rate experiment..."
    END_PORT=$2
    num_clients=$(($END_PORT-$START_PORT+1))
    echo "Experiment for ${num_clients} clients:"
    for j in $(seq 5 5 100)
    do
      #echo "Running stubby..."
      cd $PDOT_STUBBY_DIR
      for i in $(seq $START_PORT $END_PORT)
      do
        #echo "Running stubby with dots-stubby-$i.yml"
        nohup sudo -b ./stubby -C $EVAL_DIR/dots-config/pdot-stubby-${i}.yml > /dev/null 2>&1 &
        sleep 1 
      done
      sleep 3 
      #echo "Running DoTS measurement..."
      cd $EVAL_DIR
      seq $START_PORT $END_PORT | parallel -j $(($END_PORT-$START_PORT+1)) ./throughput.py dots {} $j $(($END_PORT-$START_PORT+1))
      #echo "Cleaning up DoTS measurement..."
      sleep 5 
      sudo pkill stubby
      sleep 10 
    done
    ;;
esac
