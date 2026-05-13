Indexing files
==============

Indexing labels a file in the Intezer genetic database as ``trusted`` or
``malicious`` under a given family. Once indexed, future analyses recognize
the file's code reuse against that family.

Index by file path
------------------

.. code-block:: python

   from intezer_sdk import api, consts
   from intezer_sdk.file import File

   api.set_global_api('<api_key>')

   file = File(file_path='/path/to/sample.exe')
   file.index(
       index_as=consts.IndexType.MALICIOUS,
       family_name='MyFamily',
       wait=True,
   )
   print(file.index_status, file.index_id)

Index by sha256
---------------

.. code-block:: python

   file = File(sha256='<sha256>')
   file.index(index_as=consts.IndexType.TRUSTED, family_name='MyVendor', wait=True)

Asynchronous indexing
---------------------

Drop ``wait=True`` to submit without blocking, then poll later:

.. code-block:: python

   file = File(file_path='/path/to/sample.exe')
   file.index(index_as=consts.IndexType.MALICIOUS, family_name='MyFamily')
   file.wait_for_index_completion()

Family lookup
-------------

Once a family exists you can resolve it by id or name:

.. code-block:: python

   from intezer_sdk.family import Family, get_family_by_name

   family = Family.from_family_id('<family_id>')
   print(family.name, family.type, family.tags)

   same_family = get_family_by_name('MyFamily')
