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

import os
from enum import Enum


################################################################################
# Module                                                                       #
################################################################################

class ScssSecurityHelper:
    type = None
    chunks = False
    securityOptions = None
    latestVersion = 1
    messageAttributesSize = {
        'protocolVersion': 4,
        'size': 8,
        'id': 8,
        'checksumType': 8
    }
    checksumSize = {
        'MD5': 32
    }

    @staticmethod
    def load(config):
        scssSecurity = ScssSecurityHelper()
        scssSecurity.type = ScssSecurityType.fromString('none')
        if 'Security' in config:
            security = config['Security']
            if 'type' in security:
                scssSecurity.type = ScssSecurityType.fromString(security['type'])
                scssSecurity.setupToken(security)
        return scssSecurity

    def setupToken(self, configToken: dict):
        self.securityOptions = {
            'tokenSizeBytes': 2,
            'protocolVersion': ScssSecurityHelper.latestVersion,
            'tokens': None,
            'token': None,
            'checksumType': 'MD5'
        }
        for key, value in configToken.items():
            self.securityOptions[key] = configToken[key]

    def __str__(self):
        securityString = "Security Type: [{}]".format(str(ScssSecurityType.toString(self.type))) + os.linesep
        securityString += "Security Options: [{}]".format(str(self.securityOptions)) + os.linesep
        return securityString


class ScssSecurityType(Enum):
    NONE = 0
    TOKEN = 1
    CERTIFICATE = 2

    @staticmethod
    def fromString(typeName: str):
        returnData = {
            'NONE': ScssSecurityType.NONE,
            'TOKEN': ScssSecurityType.TOKEN,
            'CERTIFICATE': ScssSecurityType.CERTIFICATE
        }
        return returnData.get(typeName.upper(), ScssSecurityType.NONE)

    @staticmethod
    def toString(type):
        returnData = {
            ScssSecurityType.NONE: 'NONE',
            ScssSecurityType.TOKEN: 'TOKEN',
            ScssSecurityType.CERTIFICATE: 'CERTIFICATE'
        }
        return returnData.get(type, '')

################################################################################
#                                End of file                                   #
################################################################################
