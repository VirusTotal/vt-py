.. vt-py documentation master file, created by
   sphinx-quickstart on Mon Jul  1 10:53:48 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to vt-py's documentation!
=================================

`vt-py <https://github.com/VirusTotal/vt-py>`_ is the official Python client library
for the `VirusTotal API v3 <https://doc.virustotal.com/v3.0/reference>`_.

This library requires Python 3.7.0+, Python 2.x is not supported. This is because vt-py
makes use of the new `async/await <https://snarky.ca/how-the-heck-does-async-await-work-in-python-3-5/>`_
syntax for implementing asynchronous coroutines.

Not supporting Python 2.x was a difficult decision to make, as we are aware
that Python 2.x is still popular among VirusTotal users, but in the long run we
think it's the right one.

Python 2.7 `has its days numbered <https://pythonclock.org/>`_, and the new
concurrency features included in Python 3.5+ are perfect for creating highly
performant code without having to deal with multi-threading or
multi-processing.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   howtoinstall
   overview
   quickstart
   apireference
