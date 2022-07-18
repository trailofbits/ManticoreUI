State Management
================

ManticoreUI supports live management of states during an execution of Manticore.
You can do so by right-clicking states in the `State List` MUI widget.
A few actions are possible.


Pause/Resume
------------

Only Active/Waiting/Paused states have these options.

Use Pause to temporarily pause states.
You may then trace such states to understand where they are currently executing.
You may also wish to kill paused states if you deem them unnecessary.

Use Resume to resume paused states.
They will resume execution till paused/completed.


Kill
----

Only Active/Waiting/Paused states have this option.
Killing a state is equivalent to running `state.abandon()` and the state will be terminated forever.


Show/Hide Trace
---------------

This option only works if the `Trace Instructions` option was enabled.
Only Paused/Forked/Complete/Errored states have these options.

Using Show Trace will highlight your BinaryView at the basic blocks that have been executed.
Use this to understand where the states have executed.

Using Hide Trace will unhighlight a previously highlighted trace.


Save Trace
----------

This option only works if the `Trace Instructions` option was enabled.
Only Paused/Forked/Complete/Errored states have this option.

Using Save Trace will prompt you to select a filename to save the trace.
A DrCov_-compatible save data will be saved into that file.

This can be loaded in other tools like Lighthouse_ or similar trace visualisation tools.


.. _DrCov: https://dynamorio.org/page_drcov.html
.. _Lighthouse: https://github.com/gaasedelen/lighthouse
