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
import socket
import time

from secureclientserverservice import ScssCommon, ScssSecurityHelper


################################################################################
# Module                                                                       #
################################################################################

class ScssProtocol:
    supportedVersions = [1]

    @staticmethod
    def sendNoneData(connection, data):
        status = False
        try:
            if data:
                data = data.encode("utf8")
                connection.sendall(data)
                status = True

        except socket.timeout:
            logging.debug("Connection timeout.")

        return status

    @staticmethod
    def sendTokenData(connection, connectionSecurity, data):
        status = False
        try:
            if data and ScssProtocol._sendToken(connection, connectionSecurity):
                id = int(time.time())
                dataChecksumType = connectionSecurity.securityOptions['checksumType']
                data = data.encode("utf8")
                dataLength = len(data)
                dataChecksum = ScssCommon.md5(data).ljust(ScssSecurityHelper.checksumSize[dataChecksumType]).encode(
                    "utf8")
                dataChecksumLength = len(dataChecksum)
                size = dataLength + dataChecksumLength
                if ScssProtocol._sendConnectionAttributes(connection,
                                                          connectionSecurity,
                                                          {'size': size,
                                                           'id': id,
                                                           'dataChecksumType': dataChecksumType}):
                    # Encryption starts here
                    connection.sendall(dataChecksum)
                    connection.sendall(data)
                    status = True

        except socket.timeout:
            logging.debug("Connection timeout.")

        return status

    @staticmethod
    def receiveNoneData(connection, max_buffer_size):
        receivedString = None
        try:
            receivedString = ScssProtocol.__receiveAllString(connection, max_buffer_size)
        except socket.timeout:
            logging.debug("Connection timeout.")

        return receivedString

    @staticmethod
    def receiveTokenData(connection, connectionSecurity, max_buffer_size):
        receivedString = None
        try:
            if 'tokens' in connectionSecurity.securityOptions and \
                    connectionSecurity.securityOptions['tokens'] is not None and \
                    isinstance(connectionSecurity.securityOptions['tokens'], list):

                clientToken = ScssProtocol._receiveToken(connection, connectionSecurity)
                logging.info("Received token: [{}]".format(str(clientToken)))
                if clientToken in connectionSecurity.securityOptions['tokens']:
                    logging.info("Token accepted.")
                    connectionAttributes = ScssProtocol._receiveConnectionAttributes(connection,
                                                                                     connectionSecurity)
                    logging.info("Connection attributes: {}".format(str(connectionAttributes)))
                    checksumSize = ScssSecurityHelper.checksumSize['MD5']

                    if 'checksumType' in connectionAttributes and \
                            connectionAttributes['checksumType']:
                        checksumSize = ScssSecurityHelper.checksumSize[connectionAttributes['checksumType']]
                    if 'size' in connectionAttributes and \
                            isinstance(connectionAttributes['size'], int) and \
                            connectionAttributes['size'] > 0:
                        logging.info("Waiting for: {} bytes data".format(str(connectionAttributes['size'])))
                        inputFromClient = ScssProtocol.__receiveAllStringBySize(connection,
                                                                                connectionAttributes['size'],
                                                                                max_buffer_size)
                        checksum = inputFromClient[:checksumSize]
                        data = inputFromClient[checksumSize:]
                        dataChecksum = ScssCommon.md5(data.encode("utf8"))
                        if checksum.lower() == dataChecksum.lower():
                            receivedString = data

                        else:
                            logging.debug('Client checksum: [{}], data checksum [{}]'.format(checksum, dataChecksum))

        except socket.timeout:
            logging.debug("Connection timeout.")

        return receivedString

    @staticmethod
    def _sendToken(connection, connectionSecurity):
        status = False
        try:
            if 'token' in connectionSecurity.securityOptions and \
                    connectionSecurity.securityOptions['token']:
                connection.sendall(connectionSecurity.securityOptions['protocolVersion'].to_bytes(
                    connectionSecurity.messageAttributesSize['protocolVersion'], byteorder='little'))
                token = connectionSecurity.securityOptions['token']
                connection.sendall(token.ljust(connectionSecurity.securityOptions['tokenSizeBytes']).encode("utf8"))
                status = True

        except socket.timeout:
            logging.debug("Connection timeout.")

        return status

    @staticmethod
    def _sendConnectionAttributes(connection, connectionSecurity, attributes):
        status = False
        try:
            if 'checksumType' in connectionSecurity.securityOptions and \
                    connectionSecurity.securityOptions['checksumType']:
                connection.sendall((attributes['size']).to_bytes(connectionSecurity.messageAttributesSize['size'],
                                                                 byteorder='little'))  # checksum + data
                connection.sendall(
                    attributes['id'].to_bytes(connectionSecurity.messageAttributesSize['id'], byteorder='little'))
                connection.sendall(attributes['dataChecksumType'].ljust(connectionSecurity.messageAttributesSize['checksumType']).encode("utf8"))
                status = True
        except socket.timeout:
            logging.debug("Connection timeout.")

        return status

    @staticmethod
    def __isVersionSupported(version):
        return version in ScssProtocol.supportedVersions

    @staticmethod
    def _receiveToken(connection, connectionSecurity):
        tokenData = None
        try:
            if 'tokenSizeBytes' in connectionSecurity.securityOptions:
                version = connection.recv(connectionSecurity.messageAttributesSize['protocolVersion'])
                if len(version) == connectionSecurity.messageAttributesSize['protocolVersion']:
                    version = int.from_bytes(version, byteorder='little', signed=False)
                else:
                    version = None
                if ScssProtocol.__isVersionSupported(version):
                    logging.debug("Protocol version: [{}]".format(version))
                    tokenData = connection.recv(connectionSecurity.securityOptions['tokenSizeBytes'])
                    if len(tokenData) > 0:
                        tokenData = tokenData.decode("utf8").strip()
                    else:
                        tokenData = None
                else:
                    logging.debug("Not supported protocol version [{}].".format(version))
        except socket.timeout:
            logging.debug("Connection timeout.")
        return str(tokenData)

    @staticmethod
    def _receiveConnectionAttributes(connection, connectionSecurity):
        attributes = {
            'size': None,
            'id': None,
            'checksumType': None
        }
        try:
            attributes['size'] = connection.recv(connectionSecurity.messageAttributesSize['size'])
            if len(attributes['size']) == connectionSecurity.messageAttributesSize['size']:
                attributes['size'] = int.from_bytes(attributes['size'], byteorder='little', signed=False)
                attributes['id'] = connection.recv(connectionSecurity.messageAttributesSize['id'])
                if len(attributes['id']) == connectionSecurity.messageAttributesSize['id']:
                    attributes['id'] = int.from_bytes(attributes['id'], byteorder='little', signed=False)
                    attributes['checksumType'] = connection.recv(
                        connectionSecurity.messageAttributesSize['checksumType'])
                    if len(attributes['checksumType']) == connectionSecurity.messageAttributesSize['checksumType']:
                        attributes['checksumType'] = attributes['checksumType'].decode("utf8").strip()
                    else:
                        attributes['checksumType'] = None
                else:
                    attributes['id'] = None
            else:
                attributes['size'] = None
        except socket.timeout:
            logging.debug("Connection timeout.")
        except:
            logging.error("Any problems with connection attributes.")
        return attributes

    @staticmethod
    def __receiveAllStringBySize(connection, size, max_buffer_size):
        allData = []
        received = 0
        while True:
            try:
                data = connection.recv(max_buffer_size)
                received += len(data)
                logging.info("Received: {} bytes data".format(str(received)))
                if not data or size < received:
                    break
                data = data.decode("utf8")
                allData.append(data)
                if size == received:
                    break
            except socket.timeout:
                logging.debug("Connection timeout.")
                break
        return ''.join(allData)

    @staticmethod
    def __receiveAllString(connection, max_buffer_size):
        allData = []
        while True:
            try:
                data = connection.recv(max_buffer_size)
                if not data:
                    break
                data = data.decode("utf8")
                allData.append(data)
            except socket.timeout:
                logging.debug("Connection timeout.")
                break
        return ''.join(allData)

################################################################################
#                                End of file                                   #
################################################################################
