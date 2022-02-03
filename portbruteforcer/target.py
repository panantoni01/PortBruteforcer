import queue
import threading


class Target:
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
        counter = 0
        while not self.queue_full():
            password = file.readline().rstrip()
            if len(password) == 0:
                return None
            else:
                self.passwords.put(password)
                counter += 1
        return counter


class Attacker(threading.Thread):
    finish = False
    password = ""
    success = False

    def __init__(self, target: Target):
        self.target = target
        self.tries = 0
        threading.Thread.__init__(self)

    def get_password(self):
        try:
            password = self.target.passwords.get(block=False)
            return password
        except queue.Empty:
            return None
