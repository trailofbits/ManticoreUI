==========================
Manticore UI Ghidra Plugin
==========================

.. image:: https://raw.githubusercontent.com/trailofbits/manticore/master/docs/images/manticore.png
    :width: 200px
    :align: center
    :alt: Manticore

This directory provides a graphical user interface plugin for `Ghidra <https://ghidra-sre.org/>`_ to allow users to easily interact with and view progress of the `Manticore symbolic execution engine <https://github.com/trailofbits/manticore>`_ for analysis of smart contracts and native binaries.

❗ATTENTION❗ This project is experimental and may be unstable or unusable for arbitrary use-cases and targets. Please open an issue if you have any difficulties using the existing features. We will consider new feature suggestions on a case-by-case basis. If possible, please open a pull request to improve or fix the project.

Requirements
------------

We require:

* An installation of `Ghidra <https://github.com/NationalSecurityAgency/ghidra/releases>`_
* Python 3.7+ with versioned Python executable (e.g. ``python3.7``) on PATH. The version is derived from ``python3`` command.

  * Must also have Python ``shiv`` `tool <https://github.com/linkedin/shiv>`_ accessible by same versioned Python executable, i.e. ``python3.7 -m shiv --version``)

  * It is easiest to use and activate a `Python virtual environment <https://docs.python.org/3/library/venv.html>`_
* Java JDK 11+
* `Gradle <https://gradle.org/install/>`_
* ``just`` `command runner <https://github.com/casey/just>`_

Building
--------

The plugin is built with Gradle. The built plugin will be a ``zip`` file in the ``MUI/dist`` directory::
    
    $ export GHIDRA_INSTALL_DIR=<path_to_ghidra_directory>
    $ just build

If you want to run the build commands manually, please take a look at the `justfile <justfile>`_.

Installation
------------

ManticoreUI (MUI) requires a copy of Ghidra. We are currently developing against the latest release(s) (``10.1.4`` at time of writing).

Manticore only operates on native binaries within a Linux environment. The Ghidra plugin does not support EVM.

1. Build MUI Ghidra
2. Run Ghidra and navigate to ``File -> Install Extensions``. Click the green ``+`` in the top right, and select the built ``MUI`` extension zip in ``MUI/dist``
3. Restart Ghidra 

The Ghidra plugin interacts with Manticore via the MUI Server, which is bundled with the plugin.

At its present form, MUI Ghidra manifests as three Ghidra components named ``MUI Setup`` (used to specify args and run Manticore), ``MUI Log``, and ``MUI State List`` (which together display Manticore output). 

1. To run Manticore on the current binary, open the ``MUI Setup`` component via ``MUI -> Run Manticore`` in the menu.
2. Fill in Manticore and program arguments in the ``MUI Setup`` component
3. Add desired Find, Avoid, Custom, or Global Hooks.
4. Click the ``Run`` Button.
5. View log message output and a list of states and their statuses via the ``MUI Log``/``MUI State List`` components which will be visible on ``Run``. Alternatively, you can open the components manually via ``MUI -> Show Log / Show State List`` in the menu. 

Usage (Native)
--------------

Setup
~~~~~
- The ``MUI Setup`` component allows you to specify key ``manticore`` arguments
- You may add additional arguments in the ``Extra Manticore Arguments`` field at the bottom of the panel
- Click ``Run`` to being an instance of Manticore with your desired arguments
- You may run multiple Manticore instances at once

.. image:: https://user-images.githubusercontent.com/29654756/151377073-33fa879d-cece-44a8-a18b-216d47f932d1.png
    :align: center
    :height: 400
    :alt: MUI Setup

Log
~~~
- At present, ``stdout`` from ``manticore`` is output to the log
- You may stop the execution of manticore and clear the log with the Stop and Clear buttons on the toolbar
- You can switch between Manticore instances by clicking on their respective log tabs
- Closing a log tab will stop the execution of the Manticore instance associated with it

.. image:: https://user-images.githubusercontent.com/29654756/151377064-e402f91d-eace-48e7-a683-1b8e59bf2127.png
    :align: center
    :height: 400
    :alt: MUI Log

State List
~~~~~~~~~~
- The State List displays the states and their statuses of the Manticore instance whose log tab is currently being viewed
- Switching log tabs will cause the State List to show the state list of the newly-focused Manticore instance
- You may click on the State statuses to expand a list of States with that status alongside their respective IDs 
- At present, possible State statuses include ``ACTIVE``, ``WAITING``, ``PAUSED``, ``FORKED``, ``COMPLETE``, and ``ERRORED``

.. image:: https://user-images.githubusercontent.com/29654756/151377036-34cf5aa0-2fdf-43ca-a825-0f4fdec16545.png
    :align: center
    :height: 400
    :alt: State List

Setting Hooks
~~~~~~~~~~~~~
- Right-clicking on an address/instruction in the Listing component (which displays the analyzed program's disassembly) will reveal two new Menu options: ``MUI -> Toggle Find Instruction`` and ``MUI -> Toggle Avoid Instruction``
- Setting an address/instruction to ``Find`` will highlight it Green, and setting it to ``Avoid`` will highlight it Red
- Additionally, you may create a custom hook via ``MUI -> Create Custom Hook at Address``, and a dialog where you can input Python code for the custom hook will be shown
- Global hooks can be set via the Toolbar in ``MUI -> Create Global Hook``, after which the same dialog to write Python code will be shown
- You may delete set hooks via the Hook List component in the ``MUI Setup`` window

.. image:: https://user-images.githubusercontent.com/29654756/151377865-94167e03-f4a8-45ca-b6a5-5be7d1bf2004.png
    :align: center
    :height: 400
    :alt: Setting Hooks

Development
-----------

1. Fork and clone the repo
2. Install the `GhidraDev plugin <https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/GhidraDev_README.html>`_ in Eclipse
3. Import the project via ``File -> Import -> General -> Projects from Folder or Archive``
4. Link your installation of Ghidra via ``GhidraDev -> Link Ghidra``. The necessary ``.project`` and ``.pydevproject`` files will be generated for Eclipse.
5. Format your code with the included ``MUI/GhidraEclipseFormatter.xml`` (taken from upstream Ghidra) by running ``just format`` with the tool `just <https://github.com/casey/just>`_.
6. Copy the desired version of the ``muicore_server`` binary to the ``os/linux/x86_64`` directory of the plugin.
7. When you first build the plugin, a gradle method will copy any common plugin resources to the ``data`` directory and the protobuf compiler binary will generate the ``ManticoreServerGrpc.java`` and ``ManticoreServerOuterClass.java`` files to serialize messages for communication with the server.
8. Quick plugin installation is enabled by the ``just install`` command.
