package mui;

import java.awt.Color;
import java.util.ArrayList;
import java.util.HashSet;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import muicore.MUICore.AddressRequest;
import muicore.MUICore.AddressRequest.Builder;
import ghidra.program.model.address.Address;

/**
 * Provides functionality to Find/Avoid a specific address via a right-click context menu item in the Listing component.
 */
public class MUIPopupMenu extends ListingContextAction {

	private static Program program;
	public static PluginTool pluginTool;

	private HashSet<Address> findAddresses;
	private HashSet<Address> avoidAddresses;

	public MUIPopupMenu(PluginTool tool, String name) {
		super(name, name);
		pluginTool = tool;
		findAddresses = new HashSet<Address>();
		avoidAddresses = new HashSet<Address>();
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

					Builder reqBuilder = AddressRequest.newBuilder()
							.setAddress(Long.parseLong(selectedAddr.toString(), 16));

					if (findAddresses.contains(selectedAddr)) {
						findAddresses.remove(selectedAddr);
						unsetColor(selectedAddr);
						reqBuilder.setType(AddressRequest.TargetType.CLEAR);
						MUIPlugin.asyncMUICoreStub.targetAddress(reqBuilder.build(), null);
					}
					else {
						findAddresses.add(selectedAddr);
						avoidAddresses.remove(selectedAddr);
						setColor(selectedAddr, Color.GREEN);
						reqBuilder.setType(AddressRequest.TargetType.FIND);
						MUIPlugin.asyncMUICoreStub.targetAddress(reqBuilder.build(), null);

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

					Builder reqBuilder = AddressRequest.newBuilder()
							.setAddress(Long.parseLong(selectedAddr.toString(), 16));

					if (avoidAddresses.contains(selectedAddr)) {
						avoidAddresses.remove(selectedAddr);
						unsetColor(selectedAddr);
						reqBuilder.setType(AddressRequest.TargetType.CLEAR);
						MUIPlugin.asyncMUICoreStub.targetAddress(reqBuilder.build(), null);

					}
					else {
						avoidAddresses.add(selectedAddr);
						findAddresses.remove(selectedAddr);
						setColor(selectedAddr, Color.RED);
						reqBuilder.setType(AddressRequest.TargetType.AVOID);
						MUIPlugin.asyncMUICoreStub.targetAddress(reqBuilder.build(), null);
					}
				}
			};

		avoidInstruction.setPopupMenuData(new MenuData(new String[] {
			"MUI",
			"Toggle Avoid Instruction",
		}));

		pluginTool.addAction(avoidInstruction);

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
