package mui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.HashMap;

import javax.swing.AbstractAction;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.event.MouseInputAdapter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import ghidra.app.services.GoToService;
import muicore.MUICore.Hook;
import muicore.MUICore.Hook.HookType;

public class MUIHookListComponent extends JPanel {

	private JTree hookListTree;
	private JScrollPane hookListView;
	private DefaultTreeModel treeModel;

	private DefaultMutableTreeNode rootNode;
	private DefaultMutableTreeNode findNode;
	private DefaultMutableTreeNode avoidNode;
	private DefaultMutableTreeNode customNode;
	private DefaultMutableTreeNode globalNode;

	private HashMap<String, DefaultMutableTreeNode> hookLocations;

	private JPopupMenu hookListPopupMenu;
	private MUIHookUserObject rightClickedHook;

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
		customNode = new DefaultMutableTreeNode("Custom");
		globalNode = new DefaultMutableTreeNode("Global");

		rootNode.add(findNode);
		rootNode.add(avoidNode);
		rootNode.add(customNode);
		rootNode.add(globalNode);

		treeModel = new DefaultTreeModel(rootNode);

		hookListTree = new JTree(treeModel);
		hookListTree.setMinimumSize(new Dimension(0, 0));
		hookListTree.setPreferredSize(new Dimension(900, 100));
		hookListView = new JScrollPane(hookListTree);
		hookListView.setMinimumSize(new Dimension(0, 0));
		hookListTree.setPreferredSize(new Dimension(900, 100));

		JMenuItem deleteOption = new JMenuItem(new AbstractAction("Delete Hook") {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (rightClickedHook != null) {
					switch (rightClickedHook.type) {
						case FIND:
						case AVOID:
							MUIPlugin.popup.unsetColor(rightClickedHook.address);
						case CUSTOM:
						case GLOBAL:
							removeHookIfExists(rightClickedHook.name, rightClickedHook.type);
						default:
							break;
					}
				}
			}

		});

		JMenuItem editOption = new JMenuItem(new AbstractAction("Edit Hook Function Text") {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (rightClickedHook != null) {
					MUIHookCodeDialogLauncher.showEdit(rightClickedHook);
				}
			}

		});

		hookListTree.addMouseListener(new MouseInputAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				if (SwingUtilities.isRightMouseButton(e)) {
					TreePath path = hookListTree.getClosestPathForLocation(e.getX(), e.getY());
					if (path != null) {
						DefaultMutableTreeNode node =
							(DefaultMutableTreeNode) path.getLastPathComponent();
						if (node.getUserObject() instanceof MUIHookUserObject) {
							rightClickedHook = (MUIHookUserObject) node.getUserObject();
							hookListPopupMenu = new JPopupMenu();
							switch (rightClickedHook.type) {
								case CUSTOM:
								case GLOBAL:
									hookListPopupMenu.add(editOption);
								case FIND:
								case AVOID:
									hookListPopupMenu.add(deleteOption);
									break;
								default:
									break;
							}
							hookListPopupMenu.show(hookListTree, e.getX(), e.getY());
						}
					}
				}
				else if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
					TreePath path = hookListTree.getClosestPathForLocation(e.getX(), e.getY());
					if (path != null) {
						DefaultMutableTreeNode node =
							(DefaultMutableTreeNode) path.getLastPathComponent();
						if (node.getUserObject() instanceof MUIHookUserObject &&
							((MUIHookUserObject) node.getUserObject()).type != HookType.GLOBAL) {
							GoToService goToService =
								MUIPlugin.pluginTool.getService(GoToService.class);
							goToService.goTo(((MUIHookUserObject) node.getUserObject()).address);
						}
					}

				}
			}
		});
	}

	public void addHook(MUIHookUserObject hook) {
		DefaultMutableTreeNode node = new DefaultMutableTreeNode(hook);
		switch (hook.type) {
			case FIND:
				findNode.add(node);
				break;
			case AVOID:
				avoidNode.add(node);
				break;
			case CUSTOM:
				customNode.add(node);
				break;
			case GLOBAL:
				globalNode.add(node);
				break;
			default:
				break;
		}

		hookLocations.put(hook.name.toString() + hook.type.name(), node);

		// TODO: Show hook counts?

		treeModel.reload();
		expandTree();

	}

	public boolean removeHookIfExists(String name, HookType type) {
		DefaultMutableTreeNode target = hookLocations.get(name + type.name());

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
			hooks.add(nodeToMUIHook((DefaultMutableTreeNode) findNode.getChildAt(i)));
		}
		for (int i = 0; i < avoidNode.getChildCount(); i++) {
			hooks.add(nodeToMUIHook((DefaultMutableTreeNode) avoidNode.getChildAt(i)));
		}
		for (int i = 0; i < customNode.getChildCount(); i++) {
			hooks.add(nodeToMUIHook((DefaultMutableTreeNode) customNode.getChildAt(i)));
		}
		for (int i = 0; i < globalNode.getChildCount(); i++) {
			hooks.add(nodeToMUIHook((DefaultMutableTreeNode) globalNode.getChildAt(i)));
		}

		return hooks;
	}

	private void expandTree() {
		int row = 1;
		while (row++ < hookListTree.getRowCount()) {
			hookListTree.expandRow(row);
		}
	}

	private Hook nodeToMUIHook(DefaultMutableTreeNode node) {
		MUIHookUserObject hook = (MUIHookUserObject) node.getUserObject();
		return hook.toMUIHook();
	}
}
