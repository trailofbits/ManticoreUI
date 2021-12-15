package mui;

import docking.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import java.awt.*;
import java.awt.event.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.swing.*;

public class MUILogProvider extends ComponentProviderAdapter {

	private JPanel logPanel;
	private JTabbedPane logTabPane;

	public MUILogProvider(PluginTool tool, String name) {
		super(tool, name, name);
		buildLogPanel();
		setTitle("MUI Log");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(true);
	}

	private void buildLogPanel() {
		logPanel = new JPanel();
		logPanel.setLayout(new BorderLayout());
		logPanel.setMinimumSize(new Dimension(500, 300));

		logTabPane = new JTabbedPane();
		logPanel.add(logTabPane);
	}

	public void runMUI(String[] manticoreArgs) {
		MUILogContentComponent newTabContent = new MUILogContentComponent();
		newTabContent.MUIInstance.callProc(manticoreArgs);
		logTabPane.add(
			ZonedDateTime.now(ZoneId.systemDefault())
					.format(DateTimeFormatter.ofPattern("HH:mm:ss")),
			newTabContent);
		logTabPane.setTabComponentAt(
			logTabPane.getTabCount() - 1, new MUILogTabComponent(logTabPane, this));
		logTabPane.setSelectedIndex(logTabPane.getTabCount() - 1);
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
