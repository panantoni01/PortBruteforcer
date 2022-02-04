#PortBruteforcer

Simple multi-threaded python tool for brute-forcing different network services. Currently supported are:
* ftp
* ssh
* telnet

## Usage
```
Usage: portbruteforcer/main.py OPTIONS <ip_addr> <service>

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  specify destination port, if the service is not on
                        default port
  -t THREADS, --threads=THREADS
                        number of threads to lanuch (default: 8)
  -n, --nostore         don't store the result of this attack in the internal
                        database
  -l LOGIN, --login=LOGIN
                        user login that will be bruteforced
  -w WORDLIST, --wordlist=WORDLIST
                        specify a file with list of passwords
  --history             run the GUI part of this program to view info about
                        previous attacks
```
