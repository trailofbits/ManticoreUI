package mui;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.util.HashSet;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.event.MouseInputAdapter;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeExpansionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import muicore.MUICore.MUIState;
import muicore.MUICore.ControlStateRequest.StateAction;

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
	private static DefaultMutableTreeNode pausedNode;
	private static DefaultMutableTreeNode forkedNode;
	private static DefaultMutableTreeNode completeNode;
	private static DefaultMutableTreeNode erroredNode;

	public static ManticoreRunner runnerDisplayed;

	private StateUserObject rightClickedState;

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
		pausedNode = new DefaultMutableTreeNode("Paused");
		forkedNode = new DefaultMutableTreeNode("Forked");
		completeNode = new DefaultMutableTreeNode("Complete");
		erroredNode = new DefaultMutableTreeNode("Errored");

		rootNode.add(activeNode);
		rootNode.add(waitingNode);
		rootNode.add(pausedNode);
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

		JMenuItem pauseOption = new JMenuItem(new AbstractAction("Pause State") {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (rightClickedState != null) {
					runnerDisplayed.controlState(StateAction.PAUSE, rightClickedState.stateId);
				}
			}

		});

		JMenuItem resumeOption = new JMenuItem(new AbstractAction("Resume State") {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (rightClickedState != null) {
					runnerDisplayed.controlState(StateAction.RESUME, rightClickedState.stateId);
				}
			}

		});

		JMenuItem killOption = new JMenuItem(new AbstractAction("Kill State") {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (rightClickedState != null) {
					runnerDisplayed.controlState(StateAction.KILL, rightClickedState.stateId);
				}
			}

		});

		stateListTree.addMouseListener(new MouseInputAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				if (SwingUtilities.isRightMouseButton(e)) {
					TreePath path = stateListTree.getClosestPathForLocation(e.getX(), e.getY());
					if (path != null) {
						DefaultMutableTreeNode node =
							(DefaultMutableTreeNode) path.getLastPathComponent();
						if (node.getUserObject() instanceof StateUserObject) {
							rightClickedState = (StateUserObject) node.getUserObject();
							JPopupMenu stateListPopupMenu = new JPopupMenu();
							if (rightClickedState.type != StateType.FORKED &&
								rightClickedState.type != StateType.COMPLETE &&
								rightClickedState.type != StateType.ERRORED) {
								stateListPopupMenu.add(killOption);
								stateListPopupMenu.add(
									rightClickedState.type == StateType.PAUSED ? resumeOption
											: pauseOption);
							}
							stateListPopupMenu.show(stateListTree, e.getX(), e.getY());
						}
					}
				}
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
		pausedNode.removeAllChildren();
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

		runner.getActiveStates()
				.forEach((state) -> activeNode.add(stateToNode(state, StateType.ACTIVE)));
		runner.getWaitingStates()
				.forEach((state) -> waitingNode.add(stateToNode(state, StateType.WAITING)));
		runner.getPausedStates()
				.forEach((state) -> pausedNode.add(stateToNode(state, StateType.PAUSED)));
		runner.getForkedStates()
				.forEach((state) -> forkedNode.add(stateToNode(state, StateType.FORKED)));
		runner.getErroredStates()
				.forEach((state) -> erroredNode.add(stateToNode(state, StateType.ERRORED)));
		runner.getCompleteStates()
				.forEach((state) -> completeNode.add(stateToNode(state, StateType.COMPLETE)));

		int activeCount = activeNode.getChildCount();
		int waitingCount = waitingNode.getChildCount();
		int pausedCount = pausedNode.getChildCount();
		int forkedCount = forkedNode.getChildCount();
		int erroredCount = erroredNode.getChildCount();
		int completeCount = completeNode.getChildCount();

		activeNode.setUserObject(String.format("Active (%d)", activeCount));
		waitingNode.setUserObject(String.format("Waiting (%d)", waitingCount));
		pausedNode.setUserObject(String.format("Paused (%d)", pausedCount));
		forkedNode.setUserObject(String.format("Forked (%d)", forkedCount));
		erroredNode.setUserObject(String.format("Errored (%d)", erroredCount));
		completeNode.setUserObject(String.format("Complete (%d)", completeCount));

		rootNode.setUserObject(String.format("States (%d)",
			activeCount + waitingCount + pausedCount + forkedCount + erroredCount + completeCount));

		treeModel.reload();

		for (TreePath path : runner.stateListExpandedPaths) {
			stateListTree.expandPath(path);
		}
	}

	/**
	 * @param st MUIState
	 * @return Node that can be added to another parent node for the State List UI.
	 */
	private static DefaultMutableTreeNode stateToNode(MUIState st, StateType type) {
		return new DefaultMutableTreeNode(new StateUserObject(st.getStateId(), type));
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

}

enum StateType {
	ACTIVE, WAITING, PAUSED, FORKED, ERRORED, COMPLETE
}

class StateUserObject {
	public int stateId;
	public StateType type;

	public StateUserObject(int stateId, StateType type) {
		this.stateId = stateId;
		this.type = type;
	}

	@Override
	public String toString() {
		return String.format("State %d", stateId);
	}
}