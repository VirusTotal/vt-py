**********
Quickstart
**********


Get information about a file
--------------------------------

Start by importing the `vt` module:

>>> import vt

Create a client, replace `<apikey>` with your actual VirusTotal API key:

>>> client = vt.Client("<apikey>")

Ask for the file you are interested in, you can replace the hash in the example
with some other SHA-256, SHA-1 or MD5:

>>> file_obj = client.get_object("/files/44d88612fea8a8f36de82e1278abb02f")

Now `file_obj` is an instance of :class:`vt.Object` that contains information
about the requested file. This object have all the attributes returned in the
API response which are listed in the `VirusTotal API v3 documentation
<https://developers.virustotal.com/v3.0/reference#files>`_. Some examples:

>>> file_obj.size
68

>>> file_obj.sha256
'275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

>>> file_obj.type_tag
'text'

>>> file_obj.last_analysis_stats
{'failure': 0, 'harmless': 0, 'malicious': 62, 'suspicious': 0, 'timeout': 0, 'type-unsupported': 9, 'undetected': 2}


Get information about an URL
----------------------------

Create a client as explained in the previous section and ask for the desired URL
as follows:

>>> url_id = vt.url_id("http://www.virustotal.com")
>>> url_obj = client.get_object("/urls/{}".format(url_id))

Notice that in this case the code is not as straightforward as it was for getting
a file. In the case of files the hash can be used as a file identifier, but with
URLs is a bit more complicated. You must use :func:`vt.url_id` for generating the
appropriate identifier. You can find more information about why this is necessary
in: `<https://developers.virustotal.com/v3.0/reference#section-url-identifiers>`_

The returned object contains the URL attributes. Some examples:

>>> url_obj.times_submitted
213730

>>> url_obj.last_analysis_stats
{'harmless': 61, 'malicious': 0, 'suspicious': 1, 'timeout': 0, 'undetected': 8}
