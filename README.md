Instructions to test:
  1. For the sniffer code’s pcap_open_live, to get the correct interface, use ifconfig and select the one on top. This code was tested on a Google Cloud instance, in this case, the correct interface will look something like 'br-5738f31b4abe'.
  2. Go to the environment directory 
  3. Run docker-compose build.
  4. Run docker-compose up to start the docker instances.
  5. Run docker ps to list the docker instances running.
  6. Use docksh <first two digits of id> to ssh into the corresponding docker instances. You will need 3 shells to test: 1 for the victim, and 2 for the attackers.
  7. Inside the docker environment, cd into volumes to access the server code, packet sniffer code, and packet spoofer code.
  8. Use the victim instances to host the server code. Use the two attacker instances for the spoofer and sniffer.
  9. Boot up the server in victim
  10. Run sniffer in one shell then spoofer on the other shell.
  11. Watch the output to ensure the correct result. The sniffer code should receive a flag from the server multiple times.

