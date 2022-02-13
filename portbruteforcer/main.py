import sys
from argparser import argparse
from target import Target
from ssh_attack import SSHAttacker
from telnet_attack import TelnetAttacker
from ftp_attack import FTPAttacker
from dbGUI import Attack, init_database, start_GUI
from datetime import datetime


def main():
    portmap = {"ftp": 21, "ssh": 22, "telnet": 23}
    (options, target) = argparse(sys.argv, portmap)

    if options.history is True:
        session = init_database()
        start_GUI(session)
        sys.exit(0)

    f = open('/dev/null', 'w')
    sys.stderr = f

    attackers = []
    for i in range(0, options.threads):
        if target.service == "ssh":
            attacker = SSHAttacker(target)
            AttackerClass = SSHAttacker
        elif target.service == "telnet":
            attacker = TelnetAttacker(target)
            AttackerClass = TelnetAttacker
        elif target.service == "ftp":
            attacker = FTPAttacker(target)
            AttackerClass = FTPAttacker
        attackers.append(attacker)
    for attacker in attackers:
        attacker.start()

    try:
        passw_counter = 0
        with open(options.wordlist) as passwords:
            while AttackerClass.finish is False:
                # if no progress has been made -> host is probably down -> lets finish
                if Target.is_target_down(attackers, 8*options.threads):
                    AttackerClass.finish = True
                # fill the queue if it is empty and check for EOF
                if target.queue_empty():
                    (passw_put, eof) = target.queue_fill(passwords)
                    passw_counter += passw_put
                    if eof is True:
                        break
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
    print("IP addr: %s" % (target.host))
    print("Service: %s" % (target.service))
    print("Port: %d" % (target.port))
    print("Username: %s" % (target.login))
    print("Password: %s" % ("?" if not AttackerClass.success else AttackerClass.password))
    print("Total attempts: %d" % (sum(attacker.tries for attacker in attackers)))
    print("-=-=-=-=-=-=-=-=-=-=-=-=--==-=-=-=-")

    # add result to database unless user decided otherwise
    if options.nostore is False:
        attack = Attack(
            end_time=datetime.now(),
            successful=AttackerClass.success,
            ip=target.host,
            service=target.service,
            port=target.port,
            login=target.login,
            password=(None if not AttackerClass.success else AttackerClass.password),
            total_tries=sum(attacker.tries for attacker in attackers)
        )
        session = init_database()
        session.add(attack)
        session.commit()
