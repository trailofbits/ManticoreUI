package mui;

import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import ghidra.program.model.address.Address;
import muicore.MUICore.Hook.HookType;

public class MUIHookCodeDialogLauncher {

	static final String DEFAULT_CUSTOM_FUNCTION =
		"global m, addr\ndef hook(state):\n    pass\nm.hook(addr)(hook)";
	static final String DEFAULT_GLOBAL_FUNCTION =
		"global m\ndef hook(state):\n    pass\nm.hook(None)(hook)";

	public static void showCreateCustom(Address address) {
		JTextArea textArea = new JTextArea(DEFAULT_CUSTOM_FUNCTION);
		int result = JOptionPane.showConfirmDialog(null, new JScrollPane(textArea),
			"Create Custom Hook at " + address.toString(),
			JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		if (result == JOptionPane.OK_OPTION) {
			MUIPlugin.setup.setupHookList.addHook(new MUIHookUserObject(HookType.CUSTOM,
				address, textArea.getText()));
			MUIHookAddressColorizer.setColor(address, HookType.CUSTOM);
		}
	}

	public static void showCreateGlobal() {
		JTextArea textArea = new JTextArea(DEFAULT_GLOBAL_FUNCTION);
		int result = JOptionPane.showConfirmDialog(null, new JScrollPane(textArea),
			"Create Global Hook",
			JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		if (result == JOptionPane.OK_OPTION) {
			MUIPlugin.setup.setupHookList
					.addHook(new MUIHookUserObject(HookType.GLOBAL, textArea.getText()));
		}
	}

	public static void showEdit(MUIHookUserObject hookObject) {
		switch (hookObject.type) {
			case CUSTOM:
			case GLOBAL:
				JTextArea textArea = new JTextArea(hookObject.func_text);
				int result = JOptionPane.showConfirmDialog(null, new JScrollPane(textArea),
					hookObject.type == HookType.CUSTOM
							? "Edit Custom Hook at " + hookObject.address.toString()
							: "Edit Global Hook",
					JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
				if (result == JOptionPane.OK_OPTION) {
					hookObject.func_text = textArea.getText();
				}
			default:
				break;
		}
	}
}
