============
Manticore UI
============

.. image:: https://raw.githubusercontent.com/trailofbits/manticore/master/docs/images/manticore.png
    :width: 200px
    :align: center
    :alt: Manticore

The Manticore User Interface (MUI) project provides a graphical user interface plugin for different disassemblers that allows users to interact easily and view the progress of the `Manticore symbolic execution engine <https://github.com/trailofbits/manticore>`_ for analysis of smart contracts and native binaries.

We are developing MUI plugins for `Binary Ninja <https://binary.ninja/>`_ and  `Ghidra <https://ghidra-sre.org/>`_. Each plugin's respective directory contains information on how to install and use it: `binaryninja <plugins/binaryninja>`_ and `ghidra <plugins/ghidra>`_.

The `Manticore Server <server>`_ is used by the Ghidra plugin to interact with Manticore over gRPC.

❗ATTENTION❗ This project is experimental and may be unstable or unusable for arbitrary use-cases and targets. Please open an issue if you have any difficulties using the existing features. We will consider new feature suggestions on a case-by-case basis. If possible, please open a pull request to improve or fix the project.

***************
Getting Started
***************

If building from source, please pull the Git submodule(s)::

    git submodule update --init

Then, please navigate to the plugin directories: `binaryninja <plugins/binaryninja>`_ and `ghidra <plugins/ghidra>`_.
