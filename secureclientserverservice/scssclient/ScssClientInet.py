# -*- coding: utf-8 -*-
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

import socket
import logging

from secureclientserverservice import ScssSecurityHelper, ScssSecurityType
from .ScssClient import ScssClient


################################################################################
# Module                                                                       #
################################################################################

class ScssClientInet(ScssClient):
    host = port = connectionType = clientSocket = None
    max_buffer_size = 8192
    timeout = None

    def __init__(self, host, port, connectionType=socket.SOCK_STREAM):
        self.host = host
        self.port = port
        self.connectionType = connectionType

    def setConnectionTimeout(self, timeout=10):
        self.timeout = timeout
        logging.debug("Set connection timeout to: [{}]".format(str(self.timeout)))

    def setConfiguration(self, config):
        if config is not None and 'timeout' in config:
            self.timeout = int(config['timeout'])
            if self.timeout <= 0:
                self.setConnectionTimeout()
            logging.debug("Set connection timeout: {}".format(str(self.timeout)))

    def setConnectionSecurity(self, connectionSecurity: ScssSecurityHelper):
        if connectionSecurity is not None and \
                isinstance(connectionSecurity, ScssSecurityHelper):
            self.connectionSecurity = connectionSecurity
            logging.debug("Set connection security to: {}".format(str(self.connectionSecurity)))

    @staticmethod
    def connect(host, port, connectionType=socket.SOCK_STREAM):
        scssClient = ScssClientInet(host, port, connectionType)
        if scssClient._connect():
            return scssClient
        else:
            return None

    def _connect(self):
        self.clientSocket = socket.socket(socket.AF_INET, self.connectionType)
        try:
            self.clientSocket.connect((self.host, self.port))
        except (OSError, TypeError) as message:
            logging.error(message)
            self.clientSocket.close()
            self.clientSocket = None
        return self.clientSocket is not None

    def send(self, data):
        super().send(data)
        if self.timeout is None:
            self.setConnectionTimeout(self.defaultTimeout)
        if self.clientSocket:
            if self.timeout:
                logging.debug("Socket Timeout: [{}]".format(str(self.clientSocket.gettimeout())))
                self.clientSocket.settimeout(self.timeout)
                logging.debug("Set Socket Timeout to: [{}]".format(str(self.timeout)))
                logging.debug("Socket Timeout: [{}]".format(str(self.clientSocket.gettimeout())))
        return self.sendAction(data)

    def sendAction(self, data):
        if self.connectionSecurity is None:
            receivedString = self.sendNone(data)
        else:
            if self.connectionSecurity.type == ScssSecurityType.CERTIFICATE:
                receivedString = self.sendCertificate(data)
            elif self.connectionSecurity.type == ScssSecurityType.TOKEN:
                receivedString = self.sendToken(data)
            else:
                receivedString = self.sendNone(data)

        return receivedString

################################################################################
#                                End of file                                   #
################################################################################
