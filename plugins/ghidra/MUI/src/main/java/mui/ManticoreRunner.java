package mui;

import manticore_server.ManticoreServerOuterClass.NativeArguments;
import manticore_server.ManticoreServerOuterClass.ControlStateRequest;
import manticore_server.ManticoreServerOuterClass.ControlStateResponse;
import manticore_server.ManticoreServerOuterClass.ManticoreLogMessage;
import manticore_server.ManticoreServerOuterClass.ManticoreMessageList;
import manticore_server.ManticoreServerOuterClass.ManticoreState;
import manticore_server.ManticoreServerOuterClass.ManticoreStateList;
import manticore_server.ManticoreServerOuterClass.ManticoreInstance;
import manticore_server.ManticoreServerOuterClass.ManticoreRunningStatus;
import manticore_server.ManticoreServerOuterClass.TerminateResponse;
import manticore_server.ManticoreServerOuterClass.ControlStateRequest.StateAction;
import io.grpc.stub.StreamObserver;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import javax.swing.tree.TreePath;

/**
 * The class representing each instance of Manticore. Used to interact with MUI-Core server and correspondingly update UI elements.
 */
public class ManticoreRunner {

	private ManticoreInstance manticoreInstance;

	private boolean hasStarted;
	private boolean isRunning;
	private boolean wasTerminated;

	private JTextArea logText;
	private JButton stopBtn;
	private JToggleButton scrollLockBtn;

	private List<ManticoreState> activeStates;
	private List<ManticoreState> waitingStates;
	private List<ManticoreState> pausedStates;
	private List<ManticoreState> forkedStates;
	private List<ManticoreState> erroredStates;
	private List<ManticoreState> completeStates;

	public HashSet<TreePath> stateListExpandedPaths;

	public ManticoreRunner() {
		hasStarted = false;
		isRunning = false;
		wasTerminated = false;

		logText = new JTextArea();
		stopBtn = new JButton();
		scrollLockBtn = new JToggleButton();

		activeStates = new ArrayList<ManticoreState>();
		waitingStates = new ArrayList<ManticoreState>();
		pausedStates = new ArrayList<ManticoreState>();
		forkedStates = new ArrayList<ManticoreState>();
		erroredStates = new ArrayList<ManticoreState>();
		completeStates = new ArrayList<ManticoreState>();

		stateListExpandedPaths = new HashSet<TreePath>();
	}

	/**
	 * Starts Manticore with given arguments.
	 * @param nativeArgs NativeArguments object which is populated and built in the Setup Component provider.
	 */
	public void startManticore(NativeArguments nativeArgs) {

		StreamObserver<ManticoreInstance> startObserver = new StreamObserver<ManticoreInstance>() {

			@Override
			public void onCompleted() {
			}

			@Override
			public void onError(Throwable arg0) {
				logText.append(arg0.getMessage() + System.lineSeparator());
			}

			@Override
			public void onNext(ManticoreInstance mcore) {
				setManticoreInstance(mcore);
				setHasStarted(true);
				setIsRunning(true);
			}

		};

		MUIPlugin.asyncMUICoreStub.startNative(nativeArgs, startObserver);
	}

	public void setManticoreInstance(ManticoreInstance m) {
		manticoreInstance = m;
	}

	public void setIsRunning(boolean b) {
		isRunning = b;
	}

	public boolean getHasStarted() {
		return hasStarted;
	}

	public void setHasStarted(boolean b) {
		hasStarted = b;
	}

	/**
	 * Terminates Manticore, but ManticoreRunner instance stays intact and can continue to display its Logs and State List.
	 */
	public void terminateManticore() {

		StreamObserver<TerminateResponse> terminateObserver =
			new StreamObserver<TerminateResponse>() {

				public boolean errored = false;

				@Override
				public void onCompleted() {
					if (!errored) {
						setIsRunning(false);
						setWasTerminated(true);
					}
				}

				@Override
				public void onError(Throwable arg0) {
					logText.append(arg0.getMessage() + System.lineSeparator());
					errored = true;
				}

				@Override
				public void onNext(TerminateResponse resp) {
				}

			};
		MUIPlugin.asyncMUICoreStub.terminate(manticoreInstance, terminateObserver);
	}

	public boolean getWasTerminated() {
		return wasTerminated;
	}

	public void setWasTerminated(boolean b) {
		wasTerminated = b;
	}

	/**
	 * Fetches unfetched Message Logs and displays them in the associated log component.
	 */
	public void fetchMessageLogs() {

		StreamObserver<ManticoreMessageList> messageListObserver =
			new StreamObserver<ManticoreMessageList>() {

				@Override
				public void onCompleted() {
				}

				@Override
				public void onError(Throwable arg0) {
					logText.append(arg0.getMessage() + System.lineSeparator());
				}

				@Override
				public void onNext(ManticoreMessageList messageList) {
					for (ManticoreLogMessage msg : messageList.getMessagesList()) {
						logText.append(msg.getContent() + System.lineSeparator());
					}
					if (!scrollLockBtn.isSelected()) {
						logText.setCaretPosition(logText.getText().length());
					}
				}
			};

		MUIPlugin.asyncMUICoreStub.getMessageList(manticoreInstance, messageListObserver);
	}

	public JTextArea getLogText() {
		return logText;
	}

	public JButton getStopBtn() {
		return stopBtn;
	}

	public void setLogUIElems(MUILogContentComponent content) {
		logText = content.logArea;
		stopBtn = content.stopButton;
		scrollLockBtn = content.scrollLockButton;
	}

	/**
	 * Fetches State List and updates State List component if is this Manticore instance is selected.
	 */
	public void fetchStateList() {

		StreamObserver<ManticoreStateList> stateListObserver =
			new StreamObserver<ManticoreStateList>() {

				@Override
				public void onCompleted() {
				}

				@Override
				public void onError(Throwable arg0) {
					logText.append(arg0.getMessage() + System.lineSeparator());
				}

				@Override
				public void onNext(ManticoreStateList muiStateList) {
					activeStates = muiStateList.getActiveStatesList();
					waitingStates = muiStateList.getWaitingStatesList();
					pausedStates = muiStateList.getPausedStatesList();
					forkedStates = muiStateList.getForkedStatesList();
					erroredStates = muiStateList.getErroredStatesList();
					completeStates = muiStateList.getCompleteStatesList();

					if (MUIPlugin.stateList.runnerDisplayed == ManticoreRunner.this) { // tab could've changed in between fetch and onNext
						MUIPlugin.stateList.updateShownStates(ManticoreRunner.this);
					}

				}

			};

		MUIPlugin.asyncMUICoreStub.getStateList(manticoreInstance, stateListObserver);
	}

	public List<ManticoreState> getActiveStates() {
		return activeStates;
	}

	public List<ManticoreState> getWaitingStates() {
		return waitingStates;
	}

	public List<ManticoreState> getPausedStates() {
		return pausedStates;
	}

	public List<ManticoreState> getForkedStates() {
		return forkedStates;
	}

	public List<ManticoreState> getErroredStates() {
		return erroredStates;
	}

	public List<ManticoreState> getCompleteStates() {
		return completeStates;
	}

	/**
	 * Fetches current running status of Manticore execution.
	 */
	public void fetchIsRunning() {

		StreamObserver<ManticoreRunningStatus> runningObserver =
			new StreamObserver<ManticoreRunningStatus>() {

				@Override
				public void onCompleted() {
				}

				@Override
				public void onError(Throwable arg0) {
					logText.append(arg0.getMessage() + System.lineSeparator());
				}

				@Override
				public void onNext(ManticoreRunningStatus status) {
					isRunning = status.getIsRunning();
				}

			};
		MUIPlugin.asyncMUICoreStub.checkManticoreRunning(manticoreInstance, runningObserver);
	}

	public boolean getIsRunning() {
		return isRunning;
	}

	/**
	 * Manually pause, resume, or kill a state in an active Manticore run.
	 * @param action StateAction enum indicating whether to PAUSE, RESUME, or KILL a state
	 * @param stateId Numeric ID of the state to perform the action on
	 */
	public void controlState(StateAction action, Integer stateId) {

		StreamObserver<ControlStateResponse> controlStateObserver =
			new StreamObserver<ControlStateResponse>() {

				@Override
				public void onCompleted() {
				}

				@Override
				public void onError(Throwable arg0) {
					logText.append(arg0.getMessage() + System.lineSeparator());
				}

				@Override
				public void onNext(ControlStateResponse resp) {
				}

			};

		ControlStateRequest request = ControlStateRequest.newBuilder()
				.setManticoreInstance(manticoreInstance)
				.setAction(action)
				.setStateId(stateId)
				.build();

		MUIPlugin.asyncMUICoreStub.controlState(request, controlStateObserver);
	}

}
