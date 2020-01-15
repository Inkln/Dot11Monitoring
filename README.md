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

### Installation of requirements

  1. Install python3 (```apt install python3 python3-pip``` on Ubuntu)

  2. Install scapy and requests libraries (```pip install scapy requests```).
  TODO use ```libpoco and libtins``` and rewrite service on C++ to get more efficiency.

  ### Usage of collector

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

 1. Unset variable ```LIMITED_DATABASE_URI``` if you want to block ability to execute sql from all users.
  Else you are able to configure ```./Docker/db_init.sql``` to set or unset permissions for user ```dot11viewer``` in database ```dot11monitor```.

 ### Build and run

 1. ```make build``` or ```docker-compose build```

 1. ```make up``` or ```docker-compose up```, moreover you may run service as daemon via ```make up-daemon``` or ```docker-compose up -d```

 1. Connect to [localhost](http://localhost) to see result. User ```admin``` will be created, and password written into logs.
 It's strongly recommended to change this password via admin panel from web interface.

### Usage of visualisation service

1. After start service will show you login and registration page. Here you should login as existing user (admin for example) or create new user. ![Register and login page][register_login_page]

1. Then you are coming to main page of app.
  ![Main page][main_page]
  Here you can see main informaion about current session and permission of user.

  > + ```User id``` - id of your user, it may be useful to communicate with admistrators to request permissions
  > + ```User login``` - username used to login, may be changed by admins
  > + ```Permissions``` - your permissions, contact with users having administration privileges to change them.

 3. After granting sufficient privilegies you will be see button in head of page
![Privilegies][main_page_grant]

4. **Monitor page**
![Monitor][monitor_page]
This page shows informaion from all collector over all time. In top of window you may change current workspace (```test``` is now selected). Discovered wifi access point are represented as yellow circles and clients as blue. Blue edges means discoveres facts of data transmission between clients and it's width conected with amount of captered data. This page update graph in real time. If many collectors captured one packed of data information about intesivity of data transfers may be incorrect. But with of edges gives us main understanding about access points usage. Access points are connected with yellow dotted edge if they working as one infrestructure.

5. **Admin page**
![User tab in admin page][admin_users]

Access to this page grants you full permissions over server.

* You may edit all users information. To change some data edit values of some fields and press ```Edit and save``` in line that you want to save. Field ```password hash``` represents pbkdf2 hashes like database, because it isn't secure to store password as plain text. But you can clear hash from field, enter new user password and save it. Hash will be computed and stored automatically. If you enter as password somithing like ```pbkdf2:.*```, this value will be used as hash. it means, that new user passwords mustn't start with string "pbkdf2:"
* You are able to see full collected database in other tabs of this page: ```"Access points", "Clients", "Data transfers", "Authorisations"```
* In tab ```"Authorisations"``` are stored best captured ```EAPOL``` 4-stage handshake result and number of tries from user to achieve that. Stage=2 and large Tries means troubles with authorisation or bruteforce attack to access points. Stage=4 and large Tries may indicate deauth attacks to clients. (Google: "dot 11 deauth attack", "wifi deauth")

6. **SQL Editor page**
![SQL Editor page][sql_editor]
![SQL results][sql_results]

This page allow users to write custom sql requests to database. You are in read only mode, can't see private schames but have access to schemas pg_catalog, pg_tables and pg_tables. Moreover, users are able to execute functions (but not create them or use filesystem functions). It means, than malicious users CAN produce troubles like via high-load requests, for example. You shouldn't grant sql permission to users you do not grant.

[register_login_page]: ./screenshots/register_login_page.png
[main_page]: ./screenshots/main_page.png
[main_page_grant]: ./screenshots/main_page_grant.png
[monitor_page]: ./screenshots/monitor_page.png
[admin_users]: ./screenshots/admin_users.png
[sql_editor]: ./screenshots/sql_editor.png
[sql_results]: ./screenshots/sql_result.png

### Development

1. Install checkers and linters ```pip install black isort pylint```
2. Make code pretty ```make pretty```
3. Run tests ```make test```
4. Check code style via pylint ```make lint```