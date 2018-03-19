LoRaWAN-parser
==============

A pure Python library to decode and encode messages for LoRaWAN radio communication, based on the specification from the [LoRa Alliance](https://www.lora-alliance.org/) (based on V1.0.2 Final). This library is compatible with Python 3.4+.

Example
=======

::

    >>> from lorawan.message import MACMessage, JoinRequest, JoinAccept, UnconfirmedDataUp, UnconfirmedDataDown
    >>> message = MACMessage.from_phy(bytes.fromhex("40F17DBE4900020001954378762B11FF0D"))
    >>> type(message)
    <class 'lorawan.message.UnconfirmedDataUp'>
    >>> message.dev_addr
    1237220849
