package mui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.ArrayList;
import java.util.HashMap;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import ghidra.program.model.address.Address;
import ghidra.util.Msg;

import muicore.MUICore.Hook;
import muicore.MUICore.Hook.HookType;

public class MUIHookListComponent extends JPanel {

	private JTree hookListTree;
	private JScrollPane hookListView;
	private DefaultTreeModel treeModel;

	private DefaultMutableTreeNode rootNode;
	private DefaultMutableTreeNode findNode;
	private DefaultMutableTreeNode avoidNode;

	private HashMap<String, DefaultMutableTreeNode> hookLocations;

	public MUIHookListComponent() {
		setLayout(new BorderLayout());
		hookLocations = new HashMap<>();
		buildHookListView();
		add(hookListView, BorderLayout.CENTER);
		setSize(new Dimension(900, 200));
		setMaximumSize(new Dimension(900, 300));
		setSize(new Dimension(900, 200));
		setMaximumSize(new Dimension(900, 300));

	}

	private void buildHookListView() {
		rootNode = new DefaultMutableTreeNode("Hooks");
		findNode = new DefaultMutableTreeNode("Find");
		avoidNode = new DefaultMutableTreeNode("Avoid");

		rootNode.add(findNode);
		rootNode.add(avoidNode);

		treeModel = new DefaultTreeModel(rootNode);

		hookListTree = new JTree(treeModel);
		hookListTree.setMinimumSize(new Dimension(0, 0));
		hookListTree.setPreferredSize(new Dimension(900, 100));
		hookListView = new JScrollPane(hookListTree);
		hookListView.setMinimumSize(new Dimension(0, 0));
		hookListTree.setPreferredSize(new Dimension(900, 100));

	}

	public void addHook(Address addr, HookType type) {
		DefaultMutableTreeNode node = addrToNode(addr);
		switch (type) {
			case FIND:
				findNode.add(node);
				break;
			case AVOID:
				avoidNode.add(node);
				break;
			default:
				Msg.warn(this, "Only FIND and AVOID hooks are currently supported!");
				// TODO: Custom + global hook support
				break;
		}

		hookLocations.put(addr.toString() + type.name(), node);

		// TODO: Show hook counts?

		treeModel.reload();
		expandTree();

	}

	public boolean removeHookIfExists(Address addr, HookType type) {
		DefaultMutableTreeNode target = hookLocations.get(addr.toString() + type.name());

		if (target == null) {
			return false;
		}

		target.removeFromParent();
		treeModel.reload();
		expandTree();
		return true;
	}

	public void clearHooks() {

		findNode.removeAllChildren();
		avoidNode.removeAllChildren();

		treeModel.reload();

	}

	public ArrayList<Hook> getAllMUIHooks() {
		ArrayList<Hook> hooks = new ArrayList<>();

		for (int i = 0; i < findNode.getChildCount(); i++) {
			hooks.add(
				nodeToMUIHook((DefaultMutableTreeNode) findNode.getChildAt(i), HookType.FIND));
		}
		for (int i = 0; i < avoidNode.getChildCount(); i++) {
			hooks.add(
				nodeToMUIHook((DefaultMutableTreeNode) avoidNode.getChildAt(i), HookType.AVOID));
		}

		return hooks;
	}

	private void expandTree() {
		int row = 1;
		while (row++ < hookListTree.getRowCount()) {
			hookListTree.expandRow(row);
		}
	}

	private DefaultMutableTreeNode addrToNode(Address addr) {
		return new DefaultMutableTreeNode(addr.toString());
	}

	private Hook nodeToMUIHook(DefaultMutableTreeNode node, HookType type) {
		return Hook.newBuilder()
				.setAddress(
					Long.parseLong(node.getUserObject().toString(), 16))
				.setType(type)
				.build();
	}
}
