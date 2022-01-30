from optparse import OptionParser


def argparse(argv, portmap):
    usage = f"Usage: {argv[0]} OPTIONS <ip_addr> <service>"
    parser = OptionParser(usage=usage)
    parser.add_option("-p", "--port", action="store", type="int", dest="port",
                      help="specify destination port, if the service is not on default port")
    parser.add_option("-t", "--threads", action="store", type="int", dest="threads", default=8,
                      help="number of threads to lanuch (default: %default)")
    parser.add_option("-n", "--nostore", action="store_false", dest="store_in_db", default=True,
                      help="don't store the result of this attack in the internal databse")
    parser.add_option("-l", "--login", action="store", type="string", dest="login", default="user",
                      help="user login that will be bruteforced")
    parser.add_option("-w", "--wordlist", action="store", type="string", dest="wordlist", default="passwords.txt",
                      help="specify a file with list of passwords")
    (options, args) = parser.parse_args(argv[1:])

    if len(args) != 2:
        parser.error("Invalid number of arguments")

    ip_addr = args[0]
    service = args[1]

    if service not in portmap.keys():
        parser.error("Specified service is not supported")

    return (options, ip_addr, service)
