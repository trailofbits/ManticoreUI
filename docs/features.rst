Features
========

ManticoreUI has various features to improve the experience of using Manticore.

There is currently a difference in features supported by the Binary Ninja and Ghidra versions of ManticoreUI.
This is outlined in the tables below:


Native Feature Table
--------------------

+-------------------------+---------------------------------+-------------------------------+
| Feature                 | Binary Ninja                    | Ghidra                        |
+=========================+=================================+===============================+
| Find/Avoid              | `✔️ <Binja Find Avoid_>`_       | `✔️ <Ghidra Find Avoid_>`_    |
+-------------------------+---------------------------------+-------------------------------+
| Custom Hooks            | `✔️ <Binja Custom Hooks_>`_     | `✔️ <Ghidra Custom Hooks_>`_  |
+-------------------------+---------------------------------+-------------------------------+
| Global Hooks            | `✔️ <Binja Global Hooks_>`_     | `✔️ <Ghidra Global Hooks_>`_  |
+-------------------------+---------------------------------+-------------------------------+
| Function Models         | `✔️ <Binja Function Models_>`_  |                               |
+-------------------------+---------------------------------+-------------------------------+
| Shared Library Support  | `✔️ <Binja Shared Lib_>`_       |                               |
+-------------------------+---------------------------------+-------------------------------+
| Live State Management   | `✔️ <Binja State Mgmt_>`_       |  `✔️ <Ghidra State Mgmt_>`_    |
+-------------------------+---------------------------------+-------------------------------+
| State Tracing           | `✔️ <Binja State Tracing_>`_    |                               |
+-------------------------+---------------------------------+-------------------------------+
| Multiple Instances      |                                 | `✔️ <Ghidra Multiple Inst_>`_ |
+-------------------------+---------------------------------+-------------------------------+



EVM Feature Table
-----------------

+----------+---------------------------+---------+
| Feature  | Binary Ninja              | Ghidra  |
+==========+===========================+=========+
| Solve    | `✔️ <Binja EVM Solve_>`_  |         |
+----------+---------------------------+---------+



.. _Binja Find Avoid: binaryninja/hooks.rst#findavoid
.. _Ghidra Find Avoid: ghidra/hooks.rst#findavoid

.. _Binja Custom Hooks: binaryninja/hooks.rst#custom-hooks
.. _Ghidra Custom Hooks: ghidra/hooks.rst#custom-hooks

.. _Binja Global Hooks: binaryninja/hooks.rst#global-hooks
.. _Ghidra Global Hooks: ghidra/hooks.rst#global-hooks

.. _Binja State Mgmt: binaryninja/state_management.rst
.. _Ghidra State Mgmt: ghidra/state_management.rst

.. _Binja Function Models: binaryninja/function_models.rst
.. _Binja Shared Lib: binaryninja/shared_library.rst
.. _Binja State Tracing: binaryninja/state_management.rst#showhide-trace

.. _Ghidra Multiple Inst: ghidra/multiple_instances.rst

.. _Binja EVM Solve: binaryninja/evm.rst
