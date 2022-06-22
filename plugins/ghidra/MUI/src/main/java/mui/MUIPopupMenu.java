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
import muicore.MUICore.Hook.HookType;
import ghidra.program.model.address.Address;

/**
 * Provides functionality to Find/Avoid a specific address via a right-click context menu item in the Listing component.
 */
public class MUIPopupMenu extends ListingContextAction {

	private static Program program;
	public static PluginTool pluginTool;

	public MUIPopupMenu(PluginTool tool, String name) {
		super(name, name);
		pluginTool = tool;
		setupMenu();
	}

	/**
	 * Clears color from the Listing component for the specified address.
	 * @param address The address to clear color from.
	 */
	public static void unsetColor(Address address) {
		ColorizingService service = pluginTool.getService(ColorizingService.class);
		int tid = program.startTransaction("unsetColor");
		service.clearBackgroundColor(address, address);
		program.endTransaction(tid, true);
	}

	/**
	 * Sets color in the Listing component for the specified address.
	 * @param address The address to clear color from.
	 * @param color The color to set for the address in the Listing component.
	 */
	public static void setColor(Address address, Color color) {
		ColorizingService service = pluginTool.getService(ColorizingService.class);
		int tid = program.startTransaction("setColor");
		service.setBackgroundColor(address, address, color);
		program.endTransaction(tid, true);

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
						unsetColor(selectedAddr);
					}
					else {
						MUIPlugin.setup.setupHookList.addHook(
							new MUIHookUserObject(HookType.FIND, selectedAddr, null));
						setColor(selectedAddr, Color.GREEN);
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
						unsetColor(selectedAddr);
					}
					else {
						MUIPlugin.setup.setupHookList.addHook(
							new MUIHookUserObject(HookType.AVOID, selectedAddr, null));
						setColor(selectedAddr, Color.RED);
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
					JTextArea textArea = new JTextArea(
						"global m, addr\ndef hook(state):\n    pass\nm.hook(addr)(hook)");
					JScrollPane scrollPane = new JScrollPane(textArea);
					int result = JOptionPane.showConfirmDialog(null, scrollPane,
						"Create Custom Hook at " + selectedAddr.toString(),
						JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
					if (result == JOptionPane.OK_OPTION) {
						String func_text = textArea.getText();
						MUIPlugin.setup.setupHookList.addHook(new MUIHookUserObject(HookType.CUSTOM,
							selectedAddr, func_text));
					}
				}
			};
		addCustomHookAtInstruction.setPopupMenuData(new MenuData(new String[] {
			"MUI",
			"Add Custom Hook at Instruction",
		}));

		pluginTool.addAction(addCustomHookAtInstruction);
	}

	/** 
	 * Called once the binary being analyzed in Ghidra has been activated.
	 * @param p the binary being analyzed in Ghidra
	 * @see MUIPlugin#programActivated(Program)
	 */
	public void setProgram(Program p) {
		program = p;
	}

}
