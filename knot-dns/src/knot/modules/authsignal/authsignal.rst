.. _mod-authsignal:

``authsignal`` – Authenticated DNSSEC Bootstrapping
===================================================

This module is able to synthesize signaling records for Authenticated DNSSEC
Bootstrapping.

https://datatracker.ietf.org/doc/draft-ietf-dnsop-dnssec-bootstrapping/

Example
-------

::

   mod-onlinesign:
     - id: authsignal
       nsec-bitmap: [CDS, CDNSKEY]

   zone:
     - domain: _signal.ns1.example.net
       module: [mod-authsignal, mod-onlinesign/authsignal]
     - domain: example.com
       dnssec-signing: on

Result:

.. code-block:: console

   $ dig +dnssec +noall +answer @127.0.0.1 CDS example.com.
   example.com.        0    IN    CDS    2061 13 2 2F748643278C41A31875F5825A46CE32D93B0F737EEA1EE52E8FDB32 84E129BC
   example.com.        0    IN    RRSIG    CDS 13 2 0 20230604095558 20230521082558 2061 example.com. IKpJD9M+FqVM9gpQAIdTypw7h+IvKwLqbFIDmqy7nw+5O8MNHMFLjCPi EZ/OjbyUswYeZrr3e3N7vhwpWVdLsA==

   $ dig +dnssec +noall +answer @127.0.0.1 CDS _dsboot.example.com._signal.ns1.example.net.
   _dsboot.example.com._signal.ns1.example.net. 0 IN CDS 2061 13 2 2F748643278C41A31875F5825A46CE32D93B0F737EEA1EE52E8FDB32 84E129BC
   _dsboot.example.com._signal.ns1.example.net. 0 IN RRSIG CDS 13 7 0 20230604095716 20230521082716 48363 _signal.ns1.example.net. UR8WHQ/WC2mD1dEJkiXk78cF0HdiodyhYNryFECBBjxHsmcvbQFQPytr tk7yhJuPAXBkRFVgdMdTy/ZqN3hHug==

Documentation to be expanded.
