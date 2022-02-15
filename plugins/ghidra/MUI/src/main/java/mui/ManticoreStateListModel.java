package mui;

import java.util.*;

import mserialize.StateOuterClass;

/**
 *
 */
public class ManticoreStateListModel {

	public HashMap<StateOuterClass.State.StateType, ArrayList<StateOuterClass.State>> stateList;

	/**
	 * Maintains a State List with statuses based on the statuses provided by the protobuf message from each Manticore instance's State server.
	 */
	public ManticoreStateListModel() {
		stateList = new HashMap();
		stateList.put(StateOuterClass.State.StateType.READY,
			new ArrayList<StateOuterClass.State>());
		stateList.put(StateOuterClass.State.StateType.BUSY, new ArrayList<StateOuterClass.State>());
		stateList.put(StateOuterClass.State.StateType.KILLED,
			new ArrayList<StateOuterClass.State>());
		stateList.put(StateOuterClass.State.StateType.TERMINATED,
			new ArrayList<StateOuterClass.State>());
		stateList.put(StateOuterClass.State.StateType.UNRECOGNIZED,
			new ArrayList<StateOuterClass.State>());
	}
}
