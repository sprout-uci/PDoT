#!/bin/sh
# Usage: ./parallel_measurement.sh 55
# This will generate Stubby instances that will listen to ports 53, 54, and 55.

START_PORT=53

option="${1}"
case ${option} in
  "one") END_PORT=$2
    echo "Running experiment for one time..."
    #echo "Running stubby..."
    cd ~/research/getdns/build/src
    for i in $(seq $START_PORT $END_PORT)
    do
      #echo "Running stubby with dots-stubby-$i.yml"
      nohup sudo -b ./stubby -C ~/research/DoTS-experiment/normal-config/normal-stubby-${i}.yml > /dev/null 2>&1 &
      sleep 1 
    done
    sleep 5 
    #echo "Running DoTS measurement..."
    cd ~/research/DoTS-experiment
    START_TIME=$(($(date +"%s%N")/1000000))
    seq $START_PORT $END_PORT | parallel ./parallel.py normal {} "$(($END_PORT-$START_PORT+1))"
    END_TIME=$(($(date +"%s%N")/1000000))
    echo "Total time: $(($END_TIME - $START_TIME))"
    #echo "Cleaning up DoTS measurement..."
    sudo pkill stubby
    ;;
  "ten") END_PORT=$2
    echo "Running experiment for ten times..."
    for j in $(seq 1 10)
    do
      #echo "Running stubby..."
      cd ~/research/getdns/build/src
      for i in $(seq $START_PORT $END_PORT)
      do
        #echo "Running stubby with dots-stubby-$i.yml"
        nohup sudo -b ./stubby -C ~/research/DoTS-experiment/normal-config/normal-stubby-${i}.yml > /dev/null 2>&1 &
        sleep 1 
      done
      sleep 5 
      #echo "Running DoTS measurement..."
      cd ~/research/DoTS-experiment
      START_TIME=$(($(date +"%s%N")/1000000))
      seq $START_PORT $END_PORT | parallel ./parallel.py normal {} "$(($END_PORT-$START_PORT+1))"
      END_TIME=$(($(date +"%s%N")/1000000))
      echo "Total time ($j): $(($END_TIME - $START_TIME))"
      #echo "Cleaning up DoTS measurement..."
      sudo pkill stubby
    done
    ;;
  "full")
    echo "Running full experiment..."
    for END_PORT in 53 54 56 57 62 72 77 102
    do
      echo "Experiment for $(($END_PORT-$START_PORT+1)) clients:"
      for j in $(seq 1 10)
      do
        #echo "Running stubby..."
        cd ~/research/getdns/build/src
        for i in $(seq $START_PORT $END_PORT)
        do
          #echo "Running stubby with dots-stubby-$i.yml"
          nohup sudo -b ./stubby -C ~/research/DoTS-experiment/normal-config/normal-stubby-${i}.yml > /dev/null 2>&1 &
          sleep 1 
        done
        sleep 5 
        #echo "Running DoTS measurement..."
        cd ~/research/DoTS-experiment
        START_TIME=$(($(date +"%s%N")/1000000))
        seq $START_PORT $END_PORT | parallel ./parallel.py normal {} "$(($END_PORT-$START_PORT+1))"
        END_TIME=$(($(date +"%s%N")/1000000))
        echo "Total time ($j): $(($END_TIME - $START_TIME))"
        #echo "Cleaning up DoTS measurement..."
        sudo pkill stubby
      done
    done
    ;;
esac
