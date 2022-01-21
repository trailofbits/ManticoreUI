package mui;

import java.util.*;

import mserialize.StateOuterClass;

public class ManticoreStateListModel {
	public HashMap<StateOuterClass.State.StateType, ArrayList<StateOuterClass.State>> stateList;

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
