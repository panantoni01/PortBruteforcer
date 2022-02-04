from optparse import OptionParser


def argparse(argv, portmap) -> (dict, str, str):
    """
    A function to parse command-line arguments and options.

    :param argv: list of raw command-line arguments
    :param portmap: dictionary, that contains service-to-port mapping
    :type portmap: dict
    :type argv: list

    :return: tuple, containing parsed options, ip adress and a service to attack
    """

    usage = f"Usage: {argv[0]} OPTIONS <ip_addr> <service>"
    parser = OptionParser(usage=usage)
    parser.add_option("-p", "--port", action="store", type="int", dest="port",
                      help="specify destination port, if the service is not on default port")
    parser.add_option("-t", "--threads", action="store", type="int", dest="threads", default=8,
                      help="number of threads to lanuch (default: %default)")
    parser.add_option("-n", "--nostore", action="store_true", dest="nostore", default=False,
                      help="don't store the result of this attack in the internal database")
    parser.add_option("-l", "--login", action="store", type="string", dest="login",
                      help="user login that will be bruteforced")
    parser.add_option("-w", "--wordlist", action="store", type="string", dest="wordlist",
                      help="specify a file with list of passwords")
    parser.add_option("--history", action="store_true", dest="history", default=False,
                      help="run the GUI part of this program to view info about previous attacks")
    (options, args) = parser.parse_args(argv[1:])

    print(options)

    if options.history is True:
        return (options, None, None)

    if options.login is None:
        parser.error("\"--login\" option is required")
    if options.wordlist is None:
        parser.error("\"--wordlist\" option is required")

    if len(args) != 2:
        parser.error("Invalid number of arguments")

    ip_addr = args[0]
    service = args[1]

    if service not in portmap.keys():
        parser.error("Specified service is not supported")

    # change default service port to the user-specified one
    if options.port is not None:
        portmap[service] = options.port

    return (options, ip_addr, service)
