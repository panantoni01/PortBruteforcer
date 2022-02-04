import queue


class Target:
    """
    A class representing the brute-force attack target.

    :param host: targets ip address
    :param service: service to be attacked
    :param port: targets port on which the chosen service listens
    :param login: user account on the target host that will be attacked
    :queue_size: size of queue, from which attacking threads will take passwords; shouldn'be less than no. of threads
    :type host: str
    :type port: int
    :type login: str
    :type queue_size: int
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
        :return: tuple - (number of passwords read, False if EOF occured, True elsewhere)
        """
        counter = 0
        while not self.queue_full():
            password = file.readline().rstrip()
            if len(password) == 0:
                return (counter, False)
            else:
                self.passwords.put(password)
                counter += 1
        return (counter, True)

    def get_password(self):
        """Try to get new password from the queue."""
        try:
            password = self.passwords.get(block=False)
            return password
        except queue.Empty:
            return None
