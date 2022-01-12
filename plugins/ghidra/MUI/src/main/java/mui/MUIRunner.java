package mui;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;

public class MUIRunner {

	private Boolean isTerminated;
	private JTextArea logArea;
	private JButton stopButton;

	public MUIRunner(JTextArea logArea, JButton stopButton) {
		isTerminated = false;
		this.logArea = logArea;
		this.stopButton = stopButton;
	}

	public void stopProc() {
		isTerminated = true;
	}

	public void callProc(String[] command) {

		stopButton.setEnabled(true);
		logArea.append(
			"Command: " + String.join(" ", command) + System.lineSeparator() +
				System.lineSeparator());

		SwingWorker sw =
			new SwingWorker() {
				Boolean errored = false;

				@Override
				protected Object doInBackground() throws Exception {
					ProcessBuilder pb = new ProcessBuilder(command);
					try {
						Process p = pb.start();
						BufferedReader reader =
							new BufferedReader(new InputStreamReader(p.getInputStream()));
						String line = "";
						while ((line = reader.readLine()) != null && !isTerminated) {
							logArea.append(line);
							logArea.append(System.lineSeparator());
						}
						if (isTerminated) {
							p.destroy();
						}
						else {
							p.waitFor();
							final int exitValue = p.waitFor();
							if (exitValue != 0) {
								errored = true;
								try (final BufferedReader b =
									new BufferedReader(new InputStreamReader(p.getErrorStream()))) {
									String eline;
									if ((eline = b.readLine()) != null) {
										logArea.append(eline);
									}
								}
								catch (final IOException e) {
									e.printStackTrace();
								}
							}
						}
						reader.close();

					}
					catch (Exception e1) {
						errored = true;
						logArea.append(e1.getMessage());
						e1.printStackTrace();
					}
					return null;
				}

				@Override
				protected void done() {
					if (isTerminated) {
						logArea.append("Manticore stopped by user.");
					}
					else if (errored) {
						logArea.append("Error! See stack trace above.");
					}
					else {
						logArea.append("Manticore execution complete.");
					}
					stopButton.setEnabled(false);
				}
			};
		sw.execute();
	}
}
