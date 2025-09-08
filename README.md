initial commit - opsky_nfc_can_ble

*********************************************
NFC setup - PN532 NFC Hat

Enable UART -
- sudo raspi-config 
- Interface options -> Serial port -> login shell: no -> Serial port hardware: yes


*********************************************
CAN setup

sudo python3 -m pip install python3-can can-j1939 --break-system-packages


*********************************************
Other packages

sudo apt install pyzmq


