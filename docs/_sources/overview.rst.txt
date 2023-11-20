********
Overview
********

The API for this library is relatively small and shares the same concepts and
principles seen in the underlying `REST API <https://docs.virustotal.com/v3.0/reference>`_.
For this reason we highly recommend you to familiarize yourself with these
`concepts <https://docs.virustotal.com/reference/key-concepts>`_ before
continuing.

While using this library you may have the impression that it's very similar to
other general-purpose HTTP libraries like `requests <http://python-requests.org>`_,
as you will see very generic APIs like :meth:`vt.Client.get`, :meth:`vt.Client.post`
and so on. In fact, you will find yourself relying on the REST API documentation
in order to find the right endpoint where to send a request to, or learn about
the attributes exported by some object. This has been a deliberate decision.
We wanted `vt-py` to be as lightweight and generic as possible, so that changes
in the REST API don't always require a new version of this client library, but
at the same time offering the right abstractions so that you don't need to deal
with details like setting HTTP headers, serializing and deserializing JSON, etc.

So, this is not a high-level library that completely abstract you out of the
underlying REST API, quite the contrary, this library is more like a HTTP library
that has been enriched with features specifically tailored to work with the
VirusTotal API.
