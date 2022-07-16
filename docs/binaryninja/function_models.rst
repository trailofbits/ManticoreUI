Function Models
===============

Function models are Python implementations of common functions.
They can be used to override the native implementations to provide performance increases.
Read more about function models in the manticore documentation `here <Manticore Docs_>`_.


When opening a new binary, ManticoreUI will alert you to functions that have function models available for use. ::

    ###################################
    # MUI Function Model Analysis     #
    #                                 #
    # 02 function(s) match:           #
    # * 0003d400, strlen              #
    # * 0003dcf0, strcmp              #
    ###################################
    -> Use 'Add Function Model' to hook these functions


You can double click on the hex addresses listed, or navigate manually to the functions.

**Usage:** ::

    Right click on an instruction > Plugins > MUI > Add Function Model

    OR

    Select instruction > Open command palette (Cntrl-Shift-P) > MUI - Add Function Model


Doing the above will create a custom hook at the selected function to invoke the function model override.
If you wish to customise the custom hook implementing the function model, simply edit it like any other custom hook using the `Hook List`.


.. _Manticore Docs: https://manticore.readthedocs.io/en/latest/native.html#function-models