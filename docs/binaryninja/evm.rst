EVM
===

ManticoreUI has some support for the EVM features of Manticore as well.
EVM features require installation of the ethersplay_ plugin.

Load Contract
-------------

This command allows you to load a solidity contract and compile it for use with ManticoreUI.

**Usage:** ::

    Open command palette (Cntrl-P) > MUI - Load Ethereum Contract



Solve With Manticore
--------------------

For EVM, using Solve With Manticore will attempt to run through possible transactions to explore full coverage of the contract being tested.
The results will be shown at the end with a run report.

**Usage:** ::

    Open command palette (Cntrl-P) > MUI - Solve With Manticore



.. _ethersplay: https://github.com/crytic/ethersplay
