Native Hooks
============

Hooks are an essential feature for using ManticoreUI with native binaries.
They allow you to interact with the execution of Manticore through manipulating the state or manticore object.


Find/Avoid
----------

Find hooks are placed at a specific address of the binary.
When Manticore executes the instruction at that address, it will end the entire run of Manticore and log the solution for any symbolic variables present.
Use find hooks to indicate areas of code which you want to reach (e.g. a function that indicates a success condition).

**Usage:** ::

    Right click on an instruction > Plugins > MUI > Find Path to This Instruction

    OR

    Select instruction > Open command palette (Cntrl-Shift-P) > MUI - Find Path to This Instruction

Avoid hooks are placed at a specific address of the binary.
When Manticore executes the instruction at that address, it will abandon the state that executed the instruction and continue executing other active states.
Use avoid hooks to indicate areas of code which you do not want to reach (e.g. a function that indicates a error condition).

**Usage:** ::

    Right click on an instruction > Plugins > MUI > Avoid This Instruction

    OR

    Select instruction > Open command palette (Cntrl-Shift-P) > MUI - Avoid This Instruction



Custom Hooks
------------

Custom hooks are placed at a specific address of the binary.
When Manticore executes the instruction at that address, it will run the code specified by your custom hook.
Use custom hooks to perform state manipulations, or to log any output necessary (e.g. using custom hooks to change register values).

**Usage:** ::

    Right click on an instruction > Plugins > MUI > Add Custom Hook

    OR

    Select instruction > Open command palette (Cntrl-Shift-P) > MUI - Add Custom Hook



Global Hooks
------------

Global hooks are triggered for *every* instruction executed.
The hooks will run custom code provided by the user.
These can be useful for detecting certain state conditions and running corresponding actions.


**Usage:** ::

    Open command palette (Cntrl-Shift-P) > MUI - Add/Edit Global Hook