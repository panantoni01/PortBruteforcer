import threading
from target import Target


class Attacker(threading.Thread):
    """
    Base abstract class for all service-specific attackers.

    :param finish: this flag is set when all threads should finish their job
    :param password: a thread that finds valid credentials, stores the password here
    :param success: this flag is set by a thread that found valid credentials
    :type finish: bool
    :type password: str
    :type success: bool

    :param tries: number of failed and successful attempts of each thread
    :param failed_conns: number of connections errors, that occured in a row within this thread
    :param curr_password: sometimes we must try to connect with the same password several
                        times - so we need a place to keep it
    :param target: Target object that contains info about the host
    :type tries: int
    :type failed_conns: int
    :type curr_password: str
    :type target: Target
    """
    finish = False
    password = ""
    success = False

    def __init__(self, target: Target):
        self.target = target
        self.tries = 0
        self.failed_conns = 0
        self.curr_password = None
        threading.Thread.__init__(self)

    @staticmethod
    def notify_password_found(password):
        Attacker.success = True
        Attacker.password = password
        Attacker.finish = True
