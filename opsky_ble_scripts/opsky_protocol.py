"""
Copyright (C) Caterpillar Inc. All Rights Reserved.
Caterpillar: Confidential Yellow

File:        opsky_protocol.py
Description: Contains reusable definitions to support the Opsky protocol.
"""
import logging
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("opsky_protocol")

BLANK_MDID = bytes([0xFF,0xFF,0xFF,0xFF,0xFF,0xFF])
NULL_MDID = bytes([0,0,0,0,0,0])
BYTEORDER = 'big'

class Opcodes(Enum):
    """
    Opsky Protocol Opcode Enumeration Definitions
    """
    SUCCESS_RESPONSE                    = 0x0000
    SET_MDID                            = 0x0001
    GET_MDID                            = 0x0002
    AUTHENTICATION_CHALLENGE            = 0x0003
    REMOTE_START                        = 0x0004
    REMOTE_STOP                         = 0x0005
    GET_REMOTE_STATUS                   = 0x0006
    GET_REMOTE_START_FEATURE_AVAILABLE  = 0x0007
    SOUND_HORN                          = 0x0008
    TURN_WORK_LIGHTS_ON                 = 0x0009
    TURN_WORK_LIGHTS_OFF                = 0x000A
    GET_WORK_LIGHTS_STATUS              = 0x000B
    LOCK_DOOR                           = 0x000C
    UNLOCK_DOOR                         = 0x000D
    GET_DOOR_LOCK_STATUS                = 0x000E
    TURN_HVAC_ON                        = 0x000F
    TURN_HVAC_OFF                       = 0x0010
    GET_HVAC_STATUS                     = 0x0011
    SET_HVAC_TEMPERATURE                = 0x0012
    GET_HVAC_TEMPERATURE                = 0x0013
    GET_FUEL_LEVEL                      = 0x0014
    GET_PRODUCT_ID                      = 0x0015
    GET_APP_SOFTWARE_VERSION            = 0x0016
    GET_LIST_OF_FAULT_AND_EVENTS        = 0x0017
    SET_NFC_ID                          = 0x0018
    SRWK_PAAK_FEATURES_ENABLED          = 0x0200
    SRWK_PAAK_FEATURES_DISABLED         = 0x0201
    GET_SRWK_PAAK_FEATURES_STATUS       = 0x0202
    SET_BLE_ZONE                        = 0x0203
    GET_BLE_ZONE                        = 0x0204
    DISCONNECT_MDID                     = 0x0205
    OPSKY_SET_PRODUCT_ID_OPCODE_CMD     = 0x0206
    UNSOLICITED_OPCODE_NOTIFICATION     = 0xFFFC
    UNSOLICITED_EVENT_NOTIFICATION      = 0xFFFD
    PENDING_RESPONSE                    = 0xFFFE
    ERROR_RESPONSE                      = 0xFFFF

class SpecificErrorCodes(Enum):
    """
    Opsky Protocol Specific Error Code Enumeration Definitions
    """
    COMMAND_NOT_SUPPORTED               = 0x0000
    MDID_NOT_AUTHORIZED                 = 0x0001
    MDID_NOT_FOUND_IN_SCHEDULE          = 0x0002
    MDID_NOT_SET                        = 0x0003
    INTERNAL_ERROR                      = 0x0004

class SpecificUnsolicitedEventCodes(Enum):
    """
    Opsky Protocol Specific Unsolicited Event Code Enumeration Definitions
    """
    MDID_WAIT_TIMEOUT                   = 0x0000
    IND_ENABLED_WAIT_TIMEOUT            = 0x0001
    AUTH_CHALLENGE_FAILED               = 0x0002
    MDID_NO_LONGER_AUTH                 = 0x0003

class BleZones(Enum):
    """
    Opsky Protocol BLE Zone Code Enumeration Definitions
    """
    NO_ZONE                             = 0x0000
    WELCOME_ZONE                        = 0x0001
    ACCESS_ZONE                         = 0x0002
    TOTAL_ZONES                         = 0x0003
    INVALID_ZONE                        = 0xFFFF

class SrwkPaakFeaturesStatus(Enum):
    """
    Opsky Protocol SRWK PAAK Features Status Code Enumeration Definitions
    """
    DISABLED                            = 0x0000
    ENABLED                             = 0x0001

def set_request_data(request_type: Opcodes, data: bytes = bytes()) -> list:
    """
    Format the request data into a buffer.

    Parameters
    ----------
    request_type: Opcodes - (Required) The Opsky Opcode Request Type value to send in the message.

    data: bytes - (Optional) Supporting data (may be required depending on the Opsky Opcode in request_type).

    Returns
    -------
    request_data: list - A list of integers containing the unsolicited notification data.
    """
    request_data = list()

    if not isinstance(data, bytes):
       data = bytes(data)

    # if isinstance(request_type, int):
    if request_type in [Opcodes.SUCCESS_RESPONSE,
                        Opcodes.ERROR_RESPONSE,
                        Opcodes.PENDING_RESPONSE,
                        Opcodes.UNSOLICITED_OPCODE_NOTIFICATION,
                        Opcodes.UNSOLICITED_EVENT_NOTIFICATION]:
        logger.error(f"Request Type: 0x{request_type.value:04X} is not a valid value.")
        return request_data

    if request_type.value not in Opcodes._value2member_map_:
        logger.error(f"Request Type: 0x{request_type.value:04X} is not a valid value.")
        return request_data

    logger.info(f"Request Type is 0x{Opcodes(request_type).value:04X} '{Opcodes(request_type).name}'")
    request_data = list(request_type.value.to_bytes(2, byteorder=BYTEORDER))

    logger.info(f"Data is {':' if data else 'empty:'} {data}")
    if data:
        request_data.extend(data)

    return request_data

def set_response_data(response_type: Opcodes,
                      opcode: Opcodes = None,
                      data: bytes = bytes(),
                      error_code: SpecificErrorCodes = None) -> list:
    """
    Format the response data into a buffer.

    Parameters
    ----------
    response_type: Opcodes - (Required) The Unsolicited Opsky Opcode Response Type value to send in the message:
       SUCCESS_RESPONSE, ERROR_RESPONSE, or PENDING_RESPONSE.

    opcode: Opcodes - (Required) The Opsky Opcode to be sent in the response.

    data: bytes - (Optional) Supporting data (may be required depending on the Opsky Opcode in response_type).

    error_code: SpecificErrorCodes - (Optional) The specific error code to use when the response type is ERROR_RESPONSE.

    Returns
    -------
    response_data: list - A list of integers containing the response data.
    """
    response_data = list()

    if not isinstance(data, bytes):
       data = bytes(data)

    if response_type not in [Opcodes.SUCCESS_RESPONSE,
                             Opcodes.ERROR_RESPONSE,
                             Opcodes.PENDING_RESPONSE]:
        logger.error(f"Response Type: 0x{response_type.value:04X} is not a valid response type value.")
        return response_data

    if opcode is None or not isinstance(opcode, Opcodes):
        logger.error(f"Opcode: {error_code} is required for a response type 0x{response_type.value:04X} {response_type.name}.")
        return response_data

    if opcode.value not in Opcodes._value2member_map_:
        logger.error(f"Opcode: 0x{opcode.value:04X} is not a valid value.")
        return response_data

    if (response_type == Opcodes.ERROR_RESPONSE) and \
       ((error_code is None) or (error_code.value not in SpecificErrorCodes._value2member_map_)):
        logger.error(f"Error Code: {f'0x{error_code:04X if error_code is None else error_code}'} is either not set or not a valid specific error code value.")
        return response_data

    logger.info(f"Response Type: 0x{response_type.value:04X} '{response_type.name}'")
    response_data = list(response_type.value.to_bytes(2, byteorder=BYTEORDER))

    logger.info(f"Opcode is 0x{opcode.value:04X} '{opcode.name}'")
    response_data.extend(list(opcode.value.to_bytes(2, byteorder=BYTEORDER)))

    logger.info(f"Data is {':' if data else 'empty:'} {data}")
    if data:
        response_data.extend(data)

    if response_type == Opcodes.ERROR_RESPONSE:
        logger.info(f"Error Code is: 0x{error_code.value:04X} '{error_code.name}'")
        response_data.extend(list(SpecificErrorCodes(error_code).value.to_bytes(2, byteorder=BYTEORDER)))

    return response_data

def set_unsolicited_notification_data(notification_type: Opcodes,
                                      data: bytes = bytes(),
                                      event: SpecificUnsolicitedEventCodes = None,
                                      opcode: Opcodes = None) -> list:
    """
    Format the unsolicited opcode/event data into a buffer.

    Parameters
    ----------
    notification_type: Opcodes - (Required) The Unsolicited Opsky Opcode Notification Type value to send in the message:
        UNSOLICITED_OPCODE_NOTIFICATION or UNSOLICITED_EVENT_NOTIFICATION.

    data: bytes - (Optional) Supporting data (may be required if notification_type=UNSOLICITED_OPCODE_NOTIFICATION).

    event: SpecificUnsolicitedEventCodes - (Required if notification_type=UNSOLICITED_EVENT_NOTIFICATION) The Specific
        Unsolicited Event Code Opsky Opcode to be used in the response for this unsolicited message.

    opcode: Opcodes - (Required if notification_type=UNSOLICITED_OPCODE_NOTIFICATION)The Opsky Opcode to be sent in the
       unsolicited notification.

    Returns
    -------
    unsolicited_response_data: list - A list of integers containing the unsolicited notification data.
    """
    unsolicited_response_data = list()

    if not isinstance(data, bytes):
       data = bytes(data)

    if notification_type not in [Opcodes.UNSOLICITED_OPCODE_NOTIFICATION,
                                 Opcodes.UNSOLICITED_EVENT_NOTIFICATION]:
        logger.error(f"Notification Type: 0x{notification_type.value:04X} is not a valid unsolicited notification type value.")
        return unsolicited_response_data

    logger.info(f"Notification Type: 0x{Opcodes(notification_type).value:04X} '{Opcodes(notification_type).name}'")
    logger.info(f"Data is {':' if data else 'empty:'} {data}")

    if notification_type == Opcodes.UNSOLICITED_EVENT_NOTIFICATION:
        if event is None:
            logger.error(f"Event code missing and required when an {Opcodes.UNSOLICITED_EVENT_NOTIFICATION.name} is used.")
            return unsolicited_response_data

        if event.value not in SpecificUnsolicitedEventCodes._value2member_map_:
            logger.error(f"Event code: 0x{event.value:04X} is not a valid value.")
            return unsolicited_response_data

        if data:
            logger.warning(f"Data is ignored due to {Opcodes.UNSOLICITED_EVENT_NOTIFICATION.name} does not require it!")

        logger.info(f"Event is 0x{SpecificUnsolicitedEventCodes(event).value:04X} {SpecificUnsolicitedEventCodes(event).name}")
        unsolicited_response_data = list(notification_type.value.to_bytes(2, byteorder=BYTEORDER))
        unsolicited_response_data.extend(list(event.value.to_bytes(2, byteorder=BYTEORDER)))

    if notification_type == Opcodes.UNSOLICITED_OPCODE_NOTIFICATION:
        if opcode is None:
            logger.error(f"Opcode missing and required when an {Opcodes.UNSOLICITED_OPCODE_NOTIFICATION.name} is used.")
            return unsolicited_response_data

        if opcode.value not in Opcodes._value2member_map_:
            logger.error(f"Opcode: 0x{opcode.value:04X} is not a valid value.")
            return unsolicited_response_data

        logger.info(f"Opcode is 0x{Opcodes(opcode).value:04X} {Opcodes(opcode).name}")

        if event:
            logger.warning(f"Event code is ignored due to {Opcodes.UNSOLICITED_OPCODE_NOTIFICATION.name} does not require it!")

        unsolicited_response_data = list(notification_type.value.to_bytes(2, byteorder=BYTEORDER))
        unsolicited_response_data.extend(list(opcode.value.to_bytes(2, byteorder=BYTEORDER)))

        if data:
            unsolicited_response_data.extend(data)

    return unsolicited_response_data

def set_response_data_v3(response_type: Opcodes,
                        opcode: Opcodes = None,
                        data: bytes = bytes(),
                        error_code: SpecificErrorCodes = None) -> list:
    """
    Format signed response data for Protocol v3: [SIG_LEN][SIGNATURE][RESPONSE_CODE][OPCODE][DATA]
    Signs the [RESPONSE_CODE][OPCODE][DATA] content.

    Parameters
    ----------
    response_type: Opcodes - (Required) The Unsolicited Opsky Opcode Response Type value to send in the message:
       SUCCESS_RESPONSE, ERROR_RESPONSE, or PENDING_RESPONSE.

    opcode: Opcodes - (Required) The Opsky Opcode to be sent in the response.

    data: bytes - (Optional) Supporting data (may be required depending on the Opsky Opcode in response_type).

    error_code: SpecificErrorCodes - (Optional) The specific error code to use when the response type is ERROR_RESPONSE.

    Returns
    -------
    response_data: list - A list of integers containing the signed response data for Protocol v3.
    """
    try:
        from ecdsa_utils import sign_data
        
        # Use the regular v2 function to get the basic response structure
        response_data = set_response_data(response_type, opcode, data, error_code)
        
        if not response_data:
            return response_data
            
        # Sign the response data
        signature = sign_data(bytes(response_data))
        sig_length = len(signature)
        
        # Format: [SIG_LEN][SIGNATURE][RESPONSE_CODE][OPCODE][DATA]
        signed_response = [sig_length] + list(signature) + response_data
        return signed_response
        
    except Exception as e:
        logger.error(f"Error signing Protocol v3 response: {e}")
        # Fallback to unsigned response
        return set_response_data(response_type, opcode, data, error_code)
