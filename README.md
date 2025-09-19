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

*********************************************
For BLE code use repository  - https://github.com/sayu-agiliad/BLE_WIFi

Branch details - 
branch : opsky_device_prototype
- The devices level flow implemented, does not uses any simulation
- It includes - BLE connection, initial authentication flow, Receive and send commands over
BLE services/characteristics
- To communicate with CAN and other modules, it uses the zmq via topics like bleToCan, canToBle and bleStatus

branch : protocol_v2
- Implementes simulation level app to support testing for opsky mobile app
*********************************************

** Refer SETUP.md for more details