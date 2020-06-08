# Cooja-Speck
Simulating Speck cipher on Cooja simulator for secure communication between Z1 motes.

Speck Cipher is a lightweight block cipher used in low powered sensory nodes.
In this project we are simulating a MQTT-SN type network including secure communication 
between nodes using Speck Cipher as an encryption layer on the top of UDP transport layer.

There is a Server(broker) and a number of clients connect to the broker and send a message(encrypted)
to the server which in turn broadcasts this message to all the avaiable clients with a Link Layer multicast.

We did this to compare the performance of different encryption algortihms in an MQTT-SN network.
