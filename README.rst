===
MUI
===

.. image:: https://raw.githubusercontent.com/trailofbits/manticore/master/docs/images/manticore.png
    :width: 200px
    :align: center
    :alt: Manticore

With the Manticore User Interface (MUI) project, we provide a graphical user interface plugin for `Binary Ninja <https://binary.ninja/>`_ to allow users to easily interact with and view progress of the `Manticore symbolic execution engine <https://github.com/trailofbits/manticore>`_ for analysis of smart contracts and native binaries.

❗ATTENTION❗ This project is under active development and may be unstable or unusable.

Requirements
------------

Aside from the Python requirements, we require the following:

* Binary Ninja (latest development version) with GUI
* ``git submodule update --init --recursive`` for Manticore submodule
* ``virtualenv`` for installing python dependencies

Installation
------------

MUI requires a copy of Binary Ninja with a GUI. Currently we are testing against the latest ``dev`` release(s) (``2.4.2901-dev`` at time of writing).

Manticore only operates on native binaries within a Linux environment. EVM support has only been tested on Mac and Linux.

Python dependencies are currently managed using ``requirements.txt`` and ``requirements-dev.txt``. You can run ``make init`` to set up a development environment.

#. Make the project available to Binary Ninja by creating a symbolic link to the plugins directory. From within the root of this repo, run the following::

    # For Mac
    $ ln -s "$(pwd)/mui" "${HOME}/Library/Application Support/Binary Ninja/plugins/mui"

    # For Linux
    $ ln -s "$(pwd)/mui" "${HOME}/.binaryninja/plugins/mui"

#. Make sure Binary Ninja knows about our python virtual environment.

   #. Open Binary Ninja's "Preferences" -> "Settings" -> "Python" and ensure the "Python Interpreter" is correctly set to the Python path associated with the current virtual environment. Reference ``venv/pyvenv.cfg`` to find the base path.

   #. Copy and paste the absolute path of the MUI project into Binary Ninja's "Python Virtual Environment Site-Packages" and add the required ``/venv/lib/python3.<minor_version>/site-packages`` suffix for the site-packages path.

   #. Restart Binary Ninja if necessary.

Development
-----------

Installing currently listed dependencies::

    $ make init
    # For Mac (will be similar for Linux)
    $ export PYTHONPATH="/Applications/Binary Ninja.app/Contents/Resources/python:/Applications/Binary Ninja.app/Contents/Resources/python3"

Activating the python virtual environment (do this before running other make commands)::

    $ source venv/bin/activate

Code style and linting can be followed by running the following::

    $ make format
    $ make lint

Tests for code without Binary Ninja interaction can be run if you have a headless version of binary ninja available, otherwise only non-Binary Ninja tests will be run::

    $ make test

Adding a new dependency can be done by editing ``requirements.txt`` or ``requirements-dev.txt`` and then running the following in the virtual environment::

    $ pip install -r requirements-dev.txt -r requirements.txt
