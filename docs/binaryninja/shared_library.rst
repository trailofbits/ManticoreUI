Shared Libraries
================

ManticoreUI has additional features to support the workflow for setting `hooks <Hooks_>`_ in external libraries.

If you wished to set a custom hook in the `malloc` function in the libc shared library, an example workflow would look like so:

1. Open the `libc.so` in Binary Ninja
2. Place any necessary hooks through the ManticoreUI interface
3. Save the project as a `.bndb` somewhere on your system (e.g. `/tmp/libc.bndb`)

Now let's say you want to apply this hook to another binary that dynamically links the libc, `/bin/ls`.

4. Open `/bin/ls` in Binary Ninja
5. Add the shared library bndb to the MUI project (`libc.bndb`)

**Usage:** ::

    Open command palette (Cntrl-P) > MUI - Manage Shared Library BNDBs

    Click Add

    Select the bndb path (e.g. `/tmp/libc.bndb`)

6. With this bndb added to your `/bin/ls` MUI project, any subsequent runs of `Solve With Manticore` will dynamically add any hooks from the `/tmp/libc.bndb` project into the current execution space.


.. _Hooks: hooks.rst