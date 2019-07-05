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

>>> file = client.get_object("/files/44d88612fea8a8f36de82e1278abb02f")

Now `file` is an instance of :class:`vt.Object` that contains information
about the requested file. This object have all the attributes returned in the
API response which are listed in the `VirusTotal API v3 documentation
<https://developers.virustotal.com/v3.0/reference#files>`_. Some examples:

>>> file.size
68

>>> file.sha256
'275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

>>> file.type_tag
'text'

>>> file.last_analysis_stats
{'failure': 0, 'harmless': 0, 'malicious': 62, 'suspicious': 0, 'timeout': 0, 'type-unsupported': 9, 'undetected': 2}


Get information about an URL
----------------------------

Create a client as explained in the previous section and ask for the desired
URL as follows:

>>> url_id = vt.url_id("http://www.virustotal.com")
>>> url = client.get_object("/urls/{}", url_id)

In this case the code is not as straightforward as it was for getting a file.
While retrieving a file any of its hashes can be used as the file identifier,
but with URLs is a bit more complicated. You must use :func:`vt.url_id` for
generating the appropriate identifier. You can find more information about why
this is necessary in:
`<https://developers.virustotal.com/v3.0/reference#section-url-identifiers>`_.

Also notice how we are using a placeholder `{}` in the path. The placeholder
will be replaced with the value of `url_id`. This works exactly like Python's
`new-style string formatting <https://pyformat.info/>`_ using the `.format()`
function. This other code is equivalent:

>>> url = client.get_object("/urls/{}".format(url_id))

The returned object contains the URL attributes. Some examples:

>>> url.times_submitted
213730

>>> url.last_analysis_stats
{'harmless': 61, 'malicious': 0, 'suspicious': 1, 'timeout': 0, 'undetected': 8}


Download a file
---------------

.. note::
    This feature is available only for premium users.

Downloading a file it's very simple, you only need to provide the hash and a
file-like object where the file's content will be written to. The target file
must be opened in `"wb"` mode:

>>> with open("/path/to/target_file", "wb") as f:
>>>   client.download_file("44d88612fea8a8f36de82e1278abb02f", f)


Start and abort a Retrohunt job
-------------------------------

.. note::
    This feature is available only for premium users.

Create an empty object of type `retrohunt_job` and set its `rules` attribute:

>>> job = vt.Object("retrohunt_job")
>>> job.rules = "rule test { condition:false }"

Post the object to the `/intelligence/retrohunt_jobs` collection:

>>> job = client.post_object("/intelligence/retrohunt_jobs", obj=job)

Notice thas `job` has been replaced with the value returned by
:func:`vt.Client.post_object`, so now `job` has additional attributes and
an object ID.

>>> job.status
'starting'

>>> job.id
'username-123456789'

With the object identifier you can ask for the job again a see it making
progress. Wait for a few seconds and do:

>>> job = client.get_object("/intelligence/retrohunt_jobs/{}", job.id)

The job status should have changed to `running`:

>>> job.status
'running'

And the progress attribute should show the completion percentage:

>>> job.progress
1.4145595

Let's abort the job:

>>> response = client.post("/intelligence/retrohunt_jobs/{}/abort", job.id)
>>> response.status
200

Here we are using :meth:`vt.Client.post` instead of :meth:`vt.Client.post_object`,
this is because the `/intelligence/retrohunt_jobs/{id}/abort
<https://developers.virustotal.com/v3.0/reference#abort-retrohunt-job>`_
endpoint doesn't expect an object, just a POST request with an empty body. The
result from :meth:`vt.Client.post` is a :class:`vt.ClientResponse` instance.


Create a LiveHunt ruleset
-------------------------

.. note::
    This feature is available only for premium users.

Create an empty object of type `hunting_ruleset` and set its `name` and
`rules` attribute:

>>> rs = vt.Object("hunting_ruleset")
>>> rs.name = "My test ruleset"
>>> rs.rules = "rule test { condition:false }"

Post the object to the `/intelligence/hunting_rulesets` collection:

>>> rs = client.post_object("/intelligence/hunting_rulesets", obj=rs)

Because we didn't set the `enabled` attribute while creating the ruleset, it
was created with `enabled=False` by default:

>>> rs.enabled
False

Let's enable the ruleset:

>>> rs.enabled = True
>>> rs = client.patch_object("/intelligence/hunting_rulesets/{}", rs.id, obj=rs)
>>> rs.enabled
True
