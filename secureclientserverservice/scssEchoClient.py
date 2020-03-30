#! /bin/sh
# -*- coding: utf-8 -*-
""":"
exec python3 $0 ${1+"$@"}
"""
# * ********************************************************************* *
# *                                                                       *
# *   Secure Client-Server Service module                                 *
# *   This file is part of secureclientserverservice.                     *
# *   This project may be found at:                                       *
# *   https://github.com/IdentityBank/Python_secureclientserverservice.   *
# *                                                                       *
# *   Copyright (C) 2020 by Identity Bank. All Rights Reserved.           *
# *   https://www.identitybank.eu - You belong to you                     *
# *                                                                       *
# *   This program is free software: you can redistribute it and/or       *
# *   modify it under the terms of the GNU Affero General Public          *
# *   License as published by the Free Software Foundation, either        *
# *   version 3 of the License, or (at your option) any later version.    *
# *                                                                       *
# *   This program is distributed in the hope that it will be useful,     *
# *   but WITHOUT ANY WARRANTY; without even the implied warranty of      *
# *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the        *
# *   GNU Affero General Public License for more details.                 *
# *                                                                       *
# *   You should have received a copy of the GNU Affero General Public    *
# *   License along with this program. If not, see                        *
# *   https://www.gnu.org/licenses/.                                      *
# *                                                                       *
# * ********************************************************************* *

################################################################################
# Import(s)                                                                    #
################################################################################

import sys
import signal
import argparse
import logging
import re

from secureclientserverservice import ScssConfig, ScssClientHelper

################################################################################
# Module Variable(s)                                                           #
################################################################################

versionString = "0.0.1"
applicationNameString = "SCSS Echo Client"
server = None


################################################################################
# Module                                                                       #
################################################################################

def parameters():
    defaultInetSocketPort = 72
    defaultInetSocketHost = "127.0.0.1"
    defaultFamily = 'INET'
    defaultUnixSocket = "/tmp/scss_unix_sockets"

    parser = argparse.ArgumentParser(description=applicationNameString)
    parser.add_argument('-v', '--version', action='version', version=applicationNameString + " - " + versionString)
    parser.add_argument('-f', '--family', choices={'INET', 'UNIX'}, default=defaultFamily, help='Server family')

    parser.add_argument('--host', default=defaultInetSocketHost,
                           help='Server host - "0.0.0.0" for all network interfaces and "127.0.0.1" or "localhost" for localhost connections. Default: ' + defaultInetSocketHost)
    parser.add_argument('--port', type=int, default=defaultInetSocketPort,
                           help='Server port. Default: ' + str(defaultInetSocketPort))
    parser.add_argument('--path', default=defaultUnixSocket,
                           help='Server socket location. Default: ' + defaultUnixSocket)

    parser.add_argument('-m', '--message', help='Message to send.', required=True)
    parser.add_argument('-t', '--type', default='STREAM', choices={'STREAM'}, help='Socket type. Default: "STREAM".',
                        required=False)
    parser.add_argument('--jscConfigFilePath', type=argparse.FileType('r'),
                        help='Server JSC config file. When config file is provided all other server configs are ignored.',
                        required=False)
    loggingLeveChoices = {
        'CRITICAL': logging.CRITICAL,
        'ERROR': logging.ERROR,
        'WARNING': logging.WARNING,
        'INFO': logging.INFO,
        'DEBUG': logging.DEBUG
    }
    parser.add_argument('-ll', '--logging_level', dest="loggingLevel", choices=loggingLeveChoices.keys(),
                        help='Output log level', required=False)
    args, leftovers = parser.parse_known_args()

    args = vars(args)

    if 'jscConfigFilePath' in args and args['jscConfigFilePath']:
        args['jscConfigFilePath'] = args['jscConfigFilePath'].name
        argsConfig = ScssConfig.getConfig(args['jscConfigFilePath'])
        if argsConfig and isinstance(argsConfig, dict):
            for argConfigKey, argConfigValue in argsConfig.items():
                if argConfigKey is not None:
                    args[argConfigKey] = argConfigValue

    if args['loggingLevel'] is None:
        level = logging.CRITICAL
    else:
        level = loggingLeveChoices.get(args['loggingLevel'], logging.CRITICAL)
    logging.basicConfig(format='[%(asctime)s][%(levelname)-8s] [%(module)-20s] - %(message)s',
                        datefmt='%Y.%m.%d %H:%M.%S', level=level)
    logging.getLogger().setLevel(level)

    return args


def main(argv=sys.argv):
    signal.signal(signal.SIGINT, handler)
    args = parameters()
    logging.info('* Arguments:')
    for key, value in args.items():
        logging.info('** [{}]: [{}]'.format(' '.join(
            ''.join([w[0].upper(), w[1:].lower()]) for w in (re.sub("([a-z])([A-Z])", "\g<1> \g<2>", key)).split()),
            value))

    if args['loggingLevel'] == 'DEBUG':
        action(args)
    else:
        try:
            action(args)
        except:
            print('Error!')


def action(args):
    client = ScssClientHelper.connect(args)
    if client is not None:
        respond = client.send(args['message'])
        print("Echo from server is {}".format(respond))


def handler(signum, frame):
    sys.exit()


# Execute main function
if __name__ == '__main__':
    main()
    sys.exit()

################################################################################
#                                End of file                                   #
################################################################################
