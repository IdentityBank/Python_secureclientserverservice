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

from secureclientserverservice import ScssProtocol
from .ScssClientInet import ScssClientInet


################################################################################
# Module                                                                       #
################################################################################

class ScssEchoClientInet(ScssClientInet):

    @staticmethod
    def connect(host, port, connectionType=socket.SOCK_STREAM):
        scssClient = ScssEchoClientInet(host, port, connectionType)
        if scssClient._connect():
            return scssClient
        else:
            return None

    def sendNone(self, data):
        receivedString = None
        try:
            logging.debug("Send [None] data.")
            ScssProtocol.sendNoneData(self.clientSocket, data)
            logging.debug("Data sent.")
            receivedString = ScssProtocol.receiveNoneData(self.clientSocket, self.max_buffer_size)
            logging.debug("Data received.")
            logging.debug("Data [{}]".format(receivedString))
        except socket.timeout:
            logging.debug("Connection timeout.")

        return receivedString

    def sendToken(self, data):
        receivedString = None
        try:
            if ScssProtocol.sendTokenData(self.clientSocket, self.connectionSecurity, data):
                receivedString = ScssProtocol.receiveTokenData(self.clientSocket, self.connectionSecurity,
                                                               self.max_buffer_size)
        except socket.timeout:
            logging.debug("Connection timeout.")

        return receivedString

    def sendCertificate(self, data):
        logging.warning('CERTIFICATE access not implemented yet!')
        return None

################################################################################
#                                End of file                                   #
################################################################################
