# Dot11Monitoring
This service provides the ability to visualize traffic using the protocols 802.11 b/g/n, 
partially supported 802.11ac/ah protocols. The service consists of 2 parts: 
collection and processing services and results visualization services. 
Parts are installed and working almost independently of each other.

---

 ## Collection service
It is possible to process information from .pcapng files collected by third-party 
utilities, such as tcpdump, wireshark or airodump-ng, as well as the ability to 
read directly from a network interface that is set to monitor mode.
  
  ### Installation
  
  1. Install python3 (```apt install python3 python3-pip``` on Ubuntu)
  
  1. Install scapy and requests libraries (```pip install scapy requests```). 
  TODO use ```libpoco and libtins``` and rewrite service on C++ to get more efficiency.
   
  ### Usage
  1. ```cd Collector```
  
  1.  
  ``` 
  python3 collection_service.py [-h] [-i INTERFACE] [-f [FILE [FILE ...]]]
                             [-H HOST] [-c [CHANNEL [CHANNEL ...]]] [-v]
                             [-t TIMEOUT] [--iterations ITERATIONS] -u
                             USERNAME [-W WORKERS] -w WORKSPACE
                             
  optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        interface to listen, mode must be set to monitor
                        manually
  -f [FILE [FILE ...]], --file [FILE [FILE ...]]
                        path to input pcap or space separated list of pcaps to
                        parse and visualize
  -H HOST, --host HOST  host to send results, localhost is default, port may
                        be specified
  -c [CHANNEL [CHANNEL ...]], --channel [CHANNEL [CHANNEL ...]]
                        channel or space separated list of channels to listen,
                        if not specified, current channel of interface will be
                        used
  -v, --verbose         show additional info in stdout
  -t TIMEOUT, --timeout TIMEOUT
                        time to parse one channel
  --iterations ITERATIONS
                        iterations over scanning channels, -1 means infinity
  -u USERNAME, --username USERNAME
                        username to use in visualisation server
  -W WORKERS, --workers WORKERS
                        num workers to process traffic, 1 is default
  -w WORKSPACE, --workspace WORKSPACE
                        name of workspace to place results

  ```
  
  #### For example
  1. ```python3 collection_service.py --host localhost:8080 --workers 4 -u admin --workspace test -f ~/dump/dump-01.cap```
  Read pcap file ``` "~/dump/dump-01.cap" ``` process them using 4 threads and send results
   to workspace ```test``` in visualization service at localhost:8080. Login in visualization server is ```admin```
   If workspace exists, data will be added to them, else workspace will be created. User must have permissions to collect 
   result via checking flag ```is_collector``` in server admin panel
   
  1. ```python3 collection_service.py -H http://my_localhost -W 4 -u admin --workspace test --interface wlan0 --channel 1 2 3 4 --iterations 4 --timeout 2```
  Scan channels 1, 2, 3, 4 via interface ```wlan0``` and send result to visualisation server. 
  Each channel is scanned for 2 seconds, the channels are replaced 4 times in a cycle. 4 threads will be created to process traffic.
  Root permissions may be required. Mode must be set to monitor manually ```(sudo iwconfig wlan0 mode Monitor)```.
   Visualization service will display results in real-time with ~5sec delay.
  
  1. ```python3 collection_service.py -H http://localhost:8080 -W 4 -u admin --workspace test --interface wlan0 --channel 1 2 3 4  --iterations -1 --timeout 2 -f ~/scripts/* ```
  Scan channels 1, 2, 3, 4 via interface ```wlan0``` and send result to visualisation server. 
  Each channel is scanned for 2 seconds, the channels are replaced infinitely in a cycle.  At the same time process all files located in the ```~/scripts/``` directory. 
  4 threads will be created to process traffic. Root permissions may be required. Mode must be set to monitor manually ```(sudo iwconfig wlan0 mode Monitor)```. 
  Visualization service will display results in real-time with ~5sec delay.
  
---
 
 ## Visualisation service
 
 This service consists from two docker containers: api and database. 
 Api is web server written in ```python3``` via ```flask``` framework and deployed under ```gunicorn```.
 Database is specially configured postgres database. Instructions how to connect your SQL database to service is below. 
 
 ### Install requirements
 
 1. ```docker >= 18.0.0```. The instructions are different for 
 different operating systems and it is better to use the [official documentation](https://docs.docker.com/install/)
 
 1. ```make``` (```apt install make``` on Ubuntu)
 
 1. ```docker-compose``` supporting your docker version. [Instruction.](https://docs.docker.com/compose/install/)
 
 ### Configure
 
 1. Set default admin password in file ```docker-compose.yml``` via set environment variable ```ADMIN_PASSWORD``` in api container.
 If environment isn't set, random secure password will be created and written into logs.
 
 1. Unset variable ```LIMITED_DATABASE_URI``` if you want to block ability to execute sql from all users. Or you are able to configure ```./Docker/db_init.sql``` to set or unset permissions for user ```dot11viewer``` in database; 
 
 ### Build and run
 
 1. ```make build``` or ```docker-compose build```

 1. ```make up``` or ```docker-compose up```, moreover you may run service as daemon via ```make up-daemon``` or ```docker-compose up -d```
 
 1. Connect to [localhost](http://localhost) to see result. User ```admin``` will be created, and password written into logs.
 It's strongly recommended to change this password via admin panel from web interface.