# PortBruteforcer

Simple multi-threaded python tool for brute-forcing different network services. This project was created for the Python course at UWr. Currently supported services are:
* ftp
* ssh
* telnet

## Usage
```
Usage: portbruteforcer OPTIONS <ip_addr> <service>

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
## How it works
At first, the attacking threads are created and then launched. Each of them will repeatably take one password from a queue located in a *Target* object, that is associated with all the threads, and will try to connect with the host. The main thread controls the queue - if it is empty, new passwords are added from the *wordlist* file. The program finishes when user decides to stop it with Ctrl+C, all the passwords have been used, correct password was found or the host seems down. In the end, statistics of the attack are added to a database (unless user decides otherwise), so that later they can be viewed using Gtk3 GUI.
