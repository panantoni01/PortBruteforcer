import queue
import threading


class Target:
    """
    A class representing the brute-force attack target.

    :param host: targets ip address
    :param port: targets port on which the chosen service listens
    :param login: user account on the target host that will be attacked
    :queue_size: size of queue, from which attacking threads will take passwords; shouldn'be less than no. of threads
    :type host: str
    :type port: int
    :type login: str
    :type queue_size: int
    """

    def __init__(self, host, port, login, queue_size):
        self.host = host
        self.port = port
        self.login = login
        self.passwords = queue.Queue(queue_size)

    def queue_empty(self) -> bool:
        return self.passwords.empty()

    def queue_full(self) -> bool:
        return self.passwords.full()

    def queue_fill(self, file) -> int:
        """
        Fill the password queue with new passwords from file

        :param file: the file to take passwords from
        :return: number of passwords read from file, None if EOF occured
        """
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
    """
    Base abstract class for all service-specific attackers.

    :param finish: this flag is set if all threads should finish their job
    :param password: the password is stored by one of the threads, that finds matching credentials
    :param success: this flag is set by a thread that found matching credentials
    :type finish: bool
    :type password: str
    :type success: bool

    :param tries: each thread counts its number of failed/successful attempts
    :param failed_conns: number of connections errors, that occured in a row within this thread
    :type tries: int
    :type failed_conns: int
    """
    finish = False
    password = ""
    success = False

    def __init__(self, target: Target):
        self.target = target
        self.tries = 0
        self.failed_conns = 0
        threading.Thread.__init__(self)

    def get_password(self):
        try:
            password = self.target.passwords.get(block=False)
            return password
        except queue.Empty:
            return None
