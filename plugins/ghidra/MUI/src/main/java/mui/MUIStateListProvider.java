package mui;

import java.awt.BorderLayout;
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
import muicore.MUICore.MUIState;

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
				runnerDisplayed.stateListExpandedPaths.remove(e.getPath());
			}

			@Override
			public void treeExpanded(TreeExpansionEvent e) {
				runnerDisplayed.stateListExpandedPaths.add(e.getPath());
			}

		});
	}

	/**
	 * Gracefully updates the Manticore runner whose State List is shown.
	 * @param runner The new Manticore runner whose State List should be shown.
	 */
	public static void changeRunner(ManticoreRunner runner) {
		clearStateTree();
		runnerDisplayed = runner;
		updateShownStates(runnerDisplayed);
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
	 * 	 * @param stateListModel Updated State List model.
	 */
	/**
	 * Updates the State List UI by getting the given Runner's state lists.
	 * @param runner ManticoreRunner whose states to display
	 */
	public static void updateShownStates(ManticoreRunner runner) {

		clearStateTree();

		runner.getActiveStates().forEach((state) -> activeNode.add(stateToNode(state)));
		runner.getWaitingStates().forEach((state) -> waitingNode.add(stateToNode(state)));
		runner.getForkedStates().forEach((state) -> forkedNode.add(stateToNode(state)));
		runner.getErroredStates().forEach((state) -> erroredNode.add(stateToNode(state)));
		runner.getCompleteStates().forEach((state) -> completeNode.add(stateToNode(state)));

		int activeCount = activeNode.getChildCount();
		int waitingCount = waitingNode.getChildCount();
		int forkedCount = forkedNode.getChildCount();
		int erroredCount = erroredNode.getChildCount();
		int completeCount = completeNode.getChildCount();

		activeNode.setUserObject(String.format("Active (%d)", activeCount));
		waitingNode.setUserObject(String.format("Waiting (%d)", waitingCount));
		forkedNode.setUserObject(String.format("Forked (%d)", forkedCount));
		erroredNode.setUserObject(String.format("Errored (%d)", erroredCount));
		completeNode.setUserObject(String.format("Complete (%d)", completeCount));

		rootNode.setUserObject(String.format("States (%d)",
			activeCount + waitingCount + forkedCount + erroredCount + completeCount));

		treeModel.reload();

		for (TreePath path : runner.stateListExpandedPaths) {
			stateListTree.expandPath(path);
		}
	}

	/**
	 * @param st MUIState
	 * @return Node that can be added to another parent node for the State List UI.
	 */
	private static DefaultMutableTreeNode stateToNode(MUIState st) {
		return new DefaultMutableTreeNode(String.format("State %d", st.getStateId()));
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

}
