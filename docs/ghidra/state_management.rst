State Management
================

ManticoreUI supports live management of states during an execution of Manticore.
You can do so by right-clicking states in the `State List` MUI widget.
A few actions are possible.


Pause
-----

Only Active/Waiting states have this option.

Use Pause to temporarily pause states.
You may then trace such states to understand where they are currently executing.
You may also wish to kill paused states if you deem them unnecessary.


Resume
------

Only Paused states have this option.

Use Resume to resume paused states.
They will resume execution till paused/completed.


Kill
----

Only Active/Waiting/Paused states have this option.
Killing a state is equivalent to running `state.abandon()` and the state will be terminated forever.
