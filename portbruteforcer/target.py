import queue


class Target:
    """
    A class representing the brute-force attack target.

    :param host: targets ip address
    :param service: service to be attacked
    :param port: targets port on which the chosen service listens
    :param login: user account on the target host that will be attacked
    :param passwords: queue with passwords, that will be used by attacking threads
    :type host: str
    :type port: int
    :type login: str
    :type passwords: queue
    """

    def __init__(self, host, service, port, login, queue_size):
        self.host = host
        self.service = service
        self.port = port
        self.login = login
        self.passwords = queue.Queue(queue_size)

    def queue_empty(self) -> bool:
        return self.passwords.empty()

    def queue_full(self) -> bool:
        return self.passwords.full()

    def queue_fill(self, file) -> (int, bool):
        """
        Fill the password queue with new passwords from file

        :param file: the file to take passwords from
        :return: tuple - (number of passwords read; True if EOF occured, False elsewhere)
        """
        counter = 0
        while not self.queue_full():
            password = file.readline().rstrip()
            if len(password) == 0:
                return (counter, True)
            else:
                self.passwords.put(password)
                counter += 1
        return (counter, False)

    def get_password(self) -> str:
        """
        Try to get new password from the queue. Dont block if the queue is empty.

        :return: password if queue non empty, None elsewhere
        """
        try:
            password = self.passwords.get(block=False)
            return password
        except queue.Empty:
            return None

    @staticmethod
    def is_target_down(attackers, failed_limit) -> bool:
        """Check if the host is down using some loose criteria.

        :param attackers: list of attacking threads
        :param failed_limit: limit of failed connections for all threads
        :type attackers: list
        :type failed_limit: int
        :return: True if host is down, False elsewhere
        """
        total_failed_conns = sum(attacker.failed_conns for attacker in attackers)
        all_non_zero = all(attacker.failed_conns != 0 for attacker in attackers)
        if total_failed_conns >= failed_limit and all_non_zero:
            return True
        return False
