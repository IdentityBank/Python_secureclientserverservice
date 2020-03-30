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

import logging
import traceback

from secureclientserverservice import ScssProtocol
from .ScssServerInet import ScssServerInet


################################################################################
# Module                                                                       #
################################################################################

class ScssEchoServerInet(ScssServerInet):

    def clientActionNone(self, connection, ip, port):
        logging.info("Waiting  for data ...")
        inputFromClient = ScssProtocol.receiveNoneData(connection, self.max_buffer_size)
        logging.info("Received: {}".format(str(inputFromClient)))
        logging.info("Sending response ...")
        ScssProtocol.sendNoneData(connection, inputFromClient)
        logging.info("Response sent.")
        connection.close()
        logging.info('Connection ' + ip + ':' + port + " ended")

    def clientActionToken(self, connection, ip, port):
        try:
            data = ScssProtocol.receiveTokenData(connection, self.connectionSecurity, self.max_buffer_size)
            logging.info("Received: {}".format(data))
            ScssProtocol.sendTokenData(connection, self.connectionSecurity, data)
        except:
            logging.debug("Error for client action token.")
            logging.debug(str(traceback.format_exc()))
        finally:
            connection.close()
            logging.info('Connection ' + ip + ':' + port + " ended")

    def clientActionCertificate(self, connection, ip, port):
        logging.warning('CERTIFICATE access not implemented yet!')

################################################################################
#                                End of file                                   #
################################################################################
