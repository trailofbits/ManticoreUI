# MUI-Ghidra
MUI support for Ghidra. This is primarily a prototype repository. See the main [MUI repo](https://github.com/trailofbits/mui) for a more complete implementation.

# Usage

At its present form, MUI-Ghidra manifests as three Ghidra components named `MUI Setup` (used to specify args and run Manticore), `MUI Log`, and `MUI State List` (which together display Manticore output). 

1. To run Manticore on the current binary, open the `MUI Setup` component via `MUI -> Run Manticore` in the menu.
2. Fill in Manticore and program arguments in the `MUI Setup` component, and click the `Run` Button. Notably, users can specify:
- the Manticore binary used (by default, a bundled binary which requires `python3.9` on PATH is used)
- the port used by Manticore's state server (by default, an open port starting from `3215` will be allocated).
3. View log message output and a list of states and their statuses via the `MUI Log`/`MUI State List` components which will be visible on `Run`. Alternatively, you can open the components manually via `MUI -> Show Log / Show State List` in the menu. 

## Components

### Setup
- The `MUI Setup` component allows you to specify key `manticore` arguments
- You may add additional arguments in the `Extra Manticore Arguments` field at the bottom of the panel
- Click `Run` to being an instance of Manticore with your desired arguments
- You may run multiple Manticore instances at once

<p align="center">
    <img src="https://user-images.githubusercontent.com/29654756/151377073-33fa879d-cece-44a8-a18b-216d47f932d1.png" alt="Image" height="400" />
</p>

### Log
- At present, `stdout` from `manticore` is output to the log
- You may stop the execution of manticore and clear the log with the Stop and Clear buttons on the toolbar
- You can switch between Manticore instances by clicking on their respective log tabs
- Closing a log tab will stop the execution of the Manticore instance associated with it

<p align="center">
    <img src="https://user-images.githubusercontent.com/29654756/151377064-e402f91d-eace-48e7-a683-1b8e59bf2127.png" alt="Image" height="400" />
</p>

### State List
- The State List displays the states and their statuses of the Manticore instance whose log tab is currently being viewed
- Switching log tabs will cause the State List to show the state list of the newly-focused Manticore instance
- You may click on the State statuses to expand a list of States with that status alongside their respective IDs 
- At present, possible State statuses include `ACTIVE`, `WAITING`, `FORKED`, `COMPLETE`, and `ERRORED`

<p align="center">
    <img src="https://user-images.githubusercontent.com/29654756/151377036-34cf5aa0-2fdf-43ca-a825-0f4fdec16545.png" alt="Image" height="400" />
</p>

### Find/Avoid Address
- Right-clicking on an address/instruction in the Listing component (which displays the analyzed program's disassembly) will reveal two new Menu options: `MUI -> Toggle Find Instruction` and `MUI -> Toggle Avoid Instruction`
- Setting an address/instruction to `Find` will highlight it Green, and setting it to `Avoid` will highlight it Red
- However, this feature is currently still **IN DEVELOPMENT** and setting addresses to `Find`/`Avoid` will have no effect
- A warning in the MUI Setup component should remind users that the feature is still unimplemented if any addresses are set to `Find`/`Avoid`

<p align="center">
    <img src="https://user-images.githubusercontent.com/29654756/151377865-94167e03-f4a8-45ca-b6a5-5be7d1bf2004.png" alt="Image" height="400" />
</p>


# Building

Build the plugin with Gradle. Built plugin will be a `zip` file in `dist` directory.

```bash
cd MUI/
GHIDRA_INSTALL_DIR=<path_to_ghidra_directory> gradle
```

# Installation

1. Ensure that Python 3.9 is installed (and that you have a `python3.9` binary). Manticore is bundled with the plugin and does not need to be separately installed, but currently requires python3.9.
2. Copy the zip file to the `Extensions` folder in your Ghidra directory 
3. Run Ghidra and select the extension in `File -> Install Extensions`
4. Restart Ghidra 

# Development

1. Fork and clone the repo
2. Install the [GhidraDev plugin](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/GhidraDev_README.html) in Eclipse
3. Import the project via `File -> Import -> General -> Projects from Folder or Archive`
4. Link your installation of Ghidra via `GhidraDev -> Link Ghidra`. The necessary `.project` and `.pydevproject` files will be generated for Eclipse.
5. Format your code with the included `MUI/GhidraEclipseFormatter.xml` (taken from upstream Ghidra) by running `just format` with the tool [just](https://github.com/casey/just).
6. When you first build the plugin, a protobuf compiler binary will generate the `StateOuterClass.java` file used for Manticore message & state list deserialization.
