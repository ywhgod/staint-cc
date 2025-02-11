run mininet: 
`sudo python3 train_env.py -t topology.json -b simple_switch_grpc -j ./build/mri.json`  will Start  network emulation that contains the BMV2 switch

topology.json is the network topology that needs to be created

Why do you need a topology file to create a network topology? --use BMV2, need to deliver a flow table. Use this file and Python to automate the delivery of flow tables.
s1-runtime.json  and s2,s3 is the flow table that each switch needs to deliver.
If you want to change the network topology, you need to configure the flow table in these files

simple_switch_grpc specify the P4 switch

mri.json is a file compiled by the P4 and runs on the switch



run train： `python3 train.py`

publish INT information to Redis message channel (rlccint_*):  `sudo python3 redis-int.py` file 
This will be trained using int information(qdepth,delay)
