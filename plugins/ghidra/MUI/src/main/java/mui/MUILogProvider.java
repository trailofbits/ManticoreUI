package mui;

import docking.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import java.awt.*;
import java.io.IOException;
import java.net.Socket;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;

public class MUILogProvider extends ComponentProviderAdapter {

	private JPanel logPanel;
	private JTabbedPane logTabPane;
	private int defPort;

	public MUILogProvider(PluginTool tool, String name) {
		super(tool, name, name);
		defPort = 3214;
		buildLogPanel();
		setTitle("MUI Log");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(false);
	}

	private void buildLogPanel() {
		logPanel = new JPanel();
		logPanel.setLayout(new BorderLayout());
		logPanel.setMinimumSize(new Dimension(500, 300));

		logTabPane = new JTabbedPane();
		logPanel.add(logTabPane);
	}

	public void runMUI(String manticoreExePath, String programPath,
			HashMap<String, JTextField> formOptions, String moreArgs) {
		MUILogContentComponent newTabContent = new MUILogContentComponent();

		newTabContent.MUIInstance
				.callProc(buildCommand("manticore", programPath, formOptions, moreArgs), defPort);

		logTabPane.add(
			ZonedDateTime.now(ZoneId.systemDefault())
					.format(DateTimeFormatter.ofPattern("HH:mm:ss")),
			newTabContent);
		logTabPane.setTabComponentAt(
			logTabPane.getTabCount() - 1, new MUILogTabComponent(logTabPane, this));
		logTabPane.setSelectedIndex(logTabPane.getTabCount() - 1);
		MUIStateListProvider.changeRunner(newTabContent.MUIInstance);
		newTabContent.requestFocusInWindow();

	}

	public String[] buildCommand(String manticoreExePath, String programPath,
			HashMap<String, JTextField> formOptions, String moreArgs) {
		ArrayList<String> f_command = new ArrayList<String>();
		f_command.add(manticoreExePath);
		String[] argv = parseCommand(formOptions.get("argv").getText());
		for (Entry<String, JTextField> option : formOptions.entrySet()) {
			if (option.getKey() == "argv")
				continue;
			for (String arg : parseCommand(option.getValue().getText())) {
				f_command.add("--".concat(option.getKey()));
				f_command.add(arg);
			}
		}

		f_command.addAll(Arrays.asList(parseCommand(moreArgs)));

		defPort = 3214;
		while (!portAvailable(defPort)) {
			defPort += 2;
		}

		f_command.add("--core.PORT");
		f_command.add(Integer.toString(defPort));

		f_command.add(programPath);
		f_command.addAll(Arrays.asList(argv));
		Msg.info(this, f_command.get(0));
		return f_command.toArray(String[]::new);
	}

	private boolean portAvailable(int port) {
		Socket s = null;
		try {
			s = new Socket("localhost", port);
			return false;
		}
		catch (IOException e) {
			return true;
		}
		finally {
			if (s != null) {
				try {
					s.close();
				}
				catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	public String[] parseCommand(String string) {
		final List<Character> WORD_DELIMITERS = Arrays.asList(' ', '\t');
		final List<Character> QUOTE_CHARACTERS = Arrays.asList('"', '\'');
		final char ESCAPE_CHARACTER = '\\';

		StringBuilder wordBuilder = new StringBuilder();
		List<String> words = new ArrayList<>();
		char quote = 0;

		for (int i = 0; i < string.length(); i++) {
			char c = string.charAt(i);

			if (c == ESCAPE_CHARACTER && i + 1 < string.length()) {
				wordBuilder.append(string.charAt(++i));
			}
			else if (WORD_DELIMITERS.contains(c) && quote == 0) {
				words.add(wordBuilder.toString());
				wordBuilder.setLength(0);
			}
			else if (quote == 0 && QUOTE_CHARACTERS.contains(c)) {
				quote = c;
			}
			else if (quote == c) {
				quote = 0;
			}
			else {
				wordBuilder.append(c);
			}
		}

		if (wordBuilder.length() > 0) {
			words.add(wordBuilder.toString());
		}

		return words.toArray(new String[0]);
	}

	public void noManticoreBinary() {
		MUILogContentComponent newTabContent = new MUILogContentComponent();
		newTabContent.logArea.append("No manticore binary found!");
		newTabContent.stopButton.setEnabled(false);
		logTabPane.add(Long.toString(Instant.now().getEpochSecond()), newTabContent);
		logTabPane.setTabComponentAt(
			logTabPane.getTabCount() - 1, new MUILogTabComponent(logTabPane, this));
	}

	public void closeLogTab(int tabIndex) {
		MUILogContentComponent curComp =
			(MUILogContentComponent) logTabPane.getComponentAt(tabIndex);
		curComp.MUIInstance.stopProc();
		logTabPane.remove(tabIndex);
	}

	@Override
	public JComponent getComponent() {
		return logPanel;
	}
}
