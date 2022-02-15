package mui;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeExpansionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import mserialize.StateOuterClass;

/**
 * Provides the "MUI State List" component used to display the State List of the Manticore instance whose MUI Log tab is currently focused.
 */
public class MUIStateListProvider extends ComponentProviderAdapter {

	private JPanel mainPanel;
	private static JTree stateListTree;
	private static DefaultTreeModel treeModel;
	private static JScrollPane stateListView;

	private static DefaultMutableTreeNode rootNode;
	private static DefaultMutableTreeNode activeNode;
	private static DefaultMutableTreeNode waitingNode;
	private static DefaultMutableTreeNode forkedNode;
	private static DefaultMutableTreeNode completeNode;
	private static DefaultMutableTreeNode erroredNode;

	public static ManticoreRunner runnerDisplayed;

	private static int maxStateId;
	private static HashSet<Integer> numsSent;

	public MUIStateListProvider(PluginTool tool, String name) {
		super(tool, name, name);
		buildStateListView();
		buildMainPanel();
		setTitle("MUI State List");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		setVisible(false);
	}

	/**
	 * Builds main component panel which contains the JTree display.
	 */
	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(stateListView, BorderLayout.CENTER);
	}

	/**
	 * Builds scrollable tree display with states categorized into the 5 statuses.
	 */
	private void buildStateListView() {
		rootNode =
			new DefaultMutableTreeNode("States");

		activeNode = new DefaultMutableTreeNode("Active");
		waitingNode = new DefaultMutableTreeNode("Waiting");
		forkedNode = new DefaultMutableTreeNode("Forked");
		completeNode = new DefaultMutableTreeNode("Complete");
		erroredNode = new DefaultMutableTreeNode("Errored");

		rootNode.add(activeNode);
		rootNode.add(waitingNode);
		rootNode.add(forkedNode);
		rootNode.add(completeNode);
		rootNode.add(erroredNode);

		treeModel = new DefaultTreeModel(rootNode);

		stateListTree = new JTree(treeModel);
		stateListView = new JScrollPane(stateListTree);

		stateListTree.addTreeExpansionListener(new TreeExpansionListener() {

			@Override
			public void treeCollapsed(TreeExpansionEvent e) {
				runnerDisplayed.expandedPaths.remove(e.getPath());
			}

			@Override
			public void treeExpanded(TreeExpansionEvent e) {
				runnerDisplayed.expandedPaths.add(e.getPath());
			}

		});
	}

	/**
	 * Gracefully updates the Manticore instance whose State List is shown.
	 * @param runner The new Manticore instance whose State List should be shown.
	 */
	public static void changeRunner(ManticoreRunner runner) {
		clearStateTree();
		runnerDisplayed = runner;
		tryUpdate(runnerDisplayed.stateListModel);
	}

	/**
	 * Helper method to clear all states from the state tree in preparation for a new update.
	 */
	private static void clearStateTree() {
		activeNode.removeAllChildren();
		waitingNode.removeAllChildren();
		forkedNode.removeAllChildren();
		completeNode.removeAllChildren();
		erroredNode.removeAllChildren();
	}

	/**
	 * Updates the State List UI using the given state list model.
	 * @param stateListModel Updated State List model.
	 */
	public static void tryUpdate(ManticoreStateListModel stateListModel) {

		maxStateId = 0;
		numsSent = new HashSet<Integer>();
		numsSent.clear();

		clearStateTree();

		stateListModel.stateList.get(StateOuterClass.State.StateType.BUSY)
				.forEach((st) -> activeNode.add(stateToNode(st)));
		stateListModel.stateList.get(StateOuterClass.State.StateType.READY)
				.forEach((st) -> waitingNode.add(stateToNode(st)));
		stateListModel.stateList.get(StateOuterClass.State.StateType.KILLED)
				.forEach((st) -> erroredNode.add(stateToNode(st)));
		stateListModel.stateList.get(StateOuterClass.State.StateType.TERMINATED)
				.forEach((st) -> completeNode.add(stateToNode(st)));

		activeNode.setUserObject(String.format("Active (%d)", activeNode.getChildCount()));
		waitingNode
				.setUserObject(String.format("Waiting (%d)", waitingNode.getChildCount()));
		completeNode.setUserObject(
			String.format("Complete (%d)", completeNode.getChildCount()));
		erroredNode
				.setUserObject(String.format("Errored (%d)", erroredNode.getChildCount()));

		for (int i = 1; i <= maxStateId; i++) {
			if (!numsSent.contains(i)) {
				forkedNode.add(new DefaultMutableTreeNode(String.format("State %d", i)));
			}
		}
		forkedNode.setUserObject(String.format("Forked (%d)", forkedNode.getChildCount()));

		rootNode.setUserObject(String.format("States (%d)", maxStateId));

		treeModel.reload();

		for (TreePath path : runnerDisplayed.expandedPaths) {
			stateListTree.expandPath(path);
		}
	}

	/**
	 * @param st State
	 * @return Node that can be added to another parent node for the State List UI.
	 */
	private static DefaultMutableTreeNode stateToNode(StateOuterClass.State st) {
		maxStateId = Math.max(maxStateId, st.getId());
		numsSent.add(st.getId());
		return new DefaultMutableTreeNode(String.format("State %d", st.getId()));
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

}
