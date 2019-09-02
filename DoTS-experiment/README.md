# Dependencies
 - parallel (`sudo apt install parallel`)
 - python3.x
 - matplotlib (`pip3 install matplotlib`)
 - numpy (`pip3 install numpy`)

# Role of each files
 - `dots-stubby.yml`, `normal-stubby.yml`: Configuration files for Stubby.
 - `latency.py`: Python script that creates and sends DNS request packets to Stubby.
 - `latency_measurement.sh`: Shell script that will setup Stubby and run `latency.py` to conduct latency experiment.
 - `latency_plot_dots_vs_unbound.py`: Python script used to create Figure 4 in the PDoT paper.
 - `dots-config/generate-config.sh`, `normal-config/generate-config.sh`: Shell scripts that generate config files for 100 Stubby instances.
 - `rate_parallel.py`: Python script that sends DNS requests to all Stubby instances all at once.
 - `dots_rate_measurement.sh`: Shell script that will setup multiple Stubby instances and run `rate_parallel.py` to conduct throughput experiment for PDoT.
 - `normal_rate_measurement.sh`: Shell script that will setup multiple Stubby instances and run `rate_parallel.py` to conduct throughput experiment for Unbound.
 - `throughput_plot_rate.py`: Python script used to create Figure 5 in the PDoT paper.

# Conducting each experiment
## Latency evaluation
 1. Make `csv` directory to store the measurement outputs: `mkdir csv`
 2. Make `image` directory to store the measurement plots: `mkdir images`
 3. Run PDoT (cf. README in DoTS directory)
 4. Update the MRENCLAVE value in `dots-stubby.yml` (cf. README in DoTS directory)
 5. Run `latency_measurement.sh`: `sudo ./latency_measurement.sh`
 6. Run `latency_plot_dots_vs_unbound.py`

## Throughput evaluation
 1. If you are running the throughput evaluation right after the latency evaluation, be sure to re-compile PDoT using the follwing command.
 ```bash
 make clean
 make SGX_MODE=HW SGX_DEBUG=1
 ```
 > **NOTE:** This is necessary because in our latency evaluation, we terminate PDoT via the `pkill` command and PDoT exits in a weird way. To guarantee SGX security properties, SGX forbids applications from exiting the enclave without using the correct CPU instruction. Whenever you encounter a problem such as PDoT not running or Stubby not correctly verifying PDoT, just run the command shown above and run PDoT again.
 2. Go into `dots-config` directory and run `generate-config.sh`
 3. Go into `normal-config` directory and run `generate-config.sh`
 4. Run PDoT
 5. Run `dots_rate_measurement.sh`
     - `sudo ./dots_rate_measurement.sh one 53 100`: Runs 1 Stubby instance (`53-53+1=1`) and sends 100 queries per second.
     - `sudo ./dots_rate_measurement.sh full_client 100`: Runs 1, 2, 4, 5, 10, 20, 25, 50 Stubby instances and sends 100 queries per second.
     - `sudo ./dots_rate_measurement.sh full_rate 53`: Runs 1 Stubby instance (`53-53+1=1`) and sends queries at varying rates, from 5 to 100 queries per second with an increment of 5.
 6. Kill PDoT (press Ctrl+C and PDoT will initiate shutdown sequence)
 7. Run Unbound
 8. Run `normal_rate_measurement.sh` (arguments for this script is the same as the one for PDoT)
 9. Kill Unbound
 10. Run `throughput_plot_rate.py`