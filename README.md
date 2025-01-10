# ACN_ARP
Advanced Computer Networks-APR Packet Processing

This implementation primarily aims to achieve the following six functionalities:

1. Verify whether the user is running the program with root privileges on a Linux system.
2. Display a command guide when the user enters an incorrect command or uses the "help" option.
3. Implement the ./arp -l -a command to capture and display all ARP packets.
4. Implement the ./arp -l <filter_ip_address> command to filter and display ARP packets for a specified IP address.
5. Implement the ./arp -q <query_ip_address> command to query the MAC address of a specified IP address.
6. Implement the ./arp <fake_mac_address> <target_ip_address> command to monitor the network environment and send a fake ARP Reply to deceive other devices when an ARP Request is sent for the specified IP address.
