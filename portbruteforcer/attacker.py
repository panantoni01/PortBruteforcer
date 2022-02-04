import threading
from target import Target


class Attacker(threading.Thread):
    """
    Base abstract class for all service-specific attackers.

    :param finish: this flag is set when all threads should finish their job
    :param password: a thread that finds valid credentials, stores the password here
    :param success: this flag is set by the thread that found valid credentials
    :type finish: bool
    :type password: str
    :type success: bool

    :param tries: number of failed and successful attempts of each thread
    :param failed_conns: number of connections errors, that occured in a row within this thread
    :param curr_password: sometimes we must try to connect with the same password several
                        times - so we need a place to keep it
    :type tries: int
    :type failed_conns: int
    :type curr_password: str
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

    @staticmethod
    def is_host_down(attackers, failed_limit) -> bool:
        total_failed_conns = sum(attacker.failed_conns for attacker in attackers)
        all_non_zero = all(attacker.failed_conns != 0 for attacker in attackers)
        if total_failed_conns >= failed_limit and all_non_zero:
            return True
        return False
