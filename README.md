# Port Scanner

## Description
This is a simple port scanner application written in C programming language, allowing users to scan for open ports on a specified host for range of ports.

## Features
- Scan single or multiple ports
- Specify a host to scan. In future can scan for multiple hosts
- Display results indicating open ports

## Installation
1. Navigate to the project directory:
    ```sh
    cd your-directory
    ```
2. Clone the repository:
    ```sh
    git clone https://github.com/Asad-360/PortScanner.git
    ```
3. Compile the source code:
    ```sh
    gcc -o main  manual.c -g
    ```

## Usage
1. Modify the configuration parameters in the source code if needed.
2. Run the compiled executable with appropriate command-line arguments:
    ```sh
    ./man -s scanme.nmap.org -p 20,8080
    ```
3. View the output to see the open ports on the specified host(s).

## Example
```sh
scanme.nmap.org resolved to 45.33.32.156 
Socket created.
Starting sniffer thread...
Starting to send syn packets
Sniffer initialising...
Received packet from 45.33.32.156:8080
Port 8080 closed
Received packet from 45.33.32.156:20
Port 20 closed
```
## Checklist
- [x] Basic port scanner
- [x] TCP Syn Ack Scanner
- [x] Timeout while scanning
- [ ] Vanilla scan
- [ ] Vanilla scan multithreaded
- [ ] Sweep scan
