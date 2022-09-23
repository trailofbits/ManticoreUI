package mui;

import java.awt.Color;
import java.util.HashSet;

import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import manticore_server.ManticoreServerOuterClass.Hook.HookType;
import ghidra.program.model.address.Address;

/**
 * Provides functionality to Find/Avoid a specific address via a right-click context menu item in the Listing component.
 */
public class MUIPopupMenu extends ListingContextAction {

	public static PluginTool pluginTool;

	public MUIPopupMenu(PluginTool tool, String name) {
		super(name, name);
		pluginTool = tool;
		setupMenu();
	}

	/**
	 * Builds the menu items in the right-click context menu of the Listing component.
	 */
	public void setupMenu() {
		pluginTool.setMenuGroup(new String[] { "MUI" }, "MUI");

		ListingContextAction findInstruction =
			new ListingContextAction("Toggle Find Instruction", "MUI") {
				@Override
				protected void actionPerformed(ListingActionContext context) {
					Address selectedAddr = context.getLocation().getAddress();

					MUIPlugin.setup.setupHookList.removeHookIfExists(selectedAddr.toString(),
						HookType.AVOID);

					if (MUIPlugin.setup.setupHookList.removeHookIfExists(selectedAddr.toString(),
						HookType.FIND)) {
						MUIHookAddressColorizer.clearColor(selectedAddr);
					}
					else {
						MUIPlugin.setup.setupHookList.addHook(
							new MUIHookUserObject(HookType.FIND, selectedAddr, null));
						MUIHookAddressColorizer.setColor(selectedAddr, HookType.FIND);
					}

				}
			};

		findInstruction.setPopupMenuData(new MenuData(new String[] {
			"MUI",
			"Toggle Find Instruction",
		}));

		pluginTool.addAction(findInstruction);

		ListingContextAction avoidInstruction =
			new ListingContextAction("Toggle Avoid Instruction", "MUI") {
				@Override
				protected void actionPerformed(ListingActionContext context) {
					Address selectedAddr = context.getLocation().getAddress();

					MUIPlugin.setup.setupHookList.removeHookIfExists(selectedAddr.toString(),
						HookType.FIND);

					if (MUIPlugin.setup.setupHookList.removeHookIfExists(selectedAddr.toString(),
						HookType.AVOID)) {
						MUIHookAddressColorizer.clearColor(selectedAddr);
					}
					else {
						MUIPlugin.setup.setupHookList.addHook(
							new MUIHookUserObject(HookType.AVOID, selectedAddr, null));
						MUIHookAddressColorizer.setColor(selectedAddr, HookType.AVOID);
					}

				}
			};

		avoidInstruction.setPopupMenuData(new MenuData(new String[] {
			"MUI",
			"Toggle Avoid Instruction",
		}));

		pluginTool.addAction(avoidInstruction);

		ListingContextAction addCustomHookAtInstruction =
			new ListingContextAction("Add Custom Hook at Instruction", "MUI") {
				@Override
				protected void actionPerformed(ListingActionContext context) {
					Address selectedAddr = context.getLocation().getAddress();
					MUIHookCodeDialogLauncher.showCreateCustom(selectedAddr);
				}
			};
		addCustomHookAtInstruction.setPopupMenuData(new MenuData(new String[] {
			"MUI",
			"Add Custom Hook at Instruction",
		}));

		pluginTool.addAction(addCustomHookAtInstruction);
	}

}
