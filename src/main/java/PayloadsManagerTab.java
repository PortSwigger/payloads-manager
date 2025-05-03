import burp.ITab;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import model.Category;
import model.Payload;
import storage.CategoryStorage;
import storage.PayloadStorage;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

public class PayloadsManagerTab implements ITab {
    private final JPanel panel;
    private final DefaultTableModel tableModel;
    private final JTable payloadTable;
    private final PayloadStorage payloadStorage;
    private final CategoryStorage categoryStorage;

    public PayloadsManagerTab(PayloadStorage payloadStorage, CategoryStorage categoryStorage) {

        this.payloadStorage = payloadStorage;
        this.categoryStorage = categoryStorage;

        panel = new JPanel(new BorderLayout());

        tableModel = new DefaultTableModel(new Object[]{"No.", "Payload Name", "Payload", "Category"}, 0);
        payloadTable = new JTable(tableModel) {
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        TableColumn column = payloadTable.getColumnModel().getColumn(0);
        column.setPreferredWidth(50);
        column.setMaxWidth(50);
        column.setMinWidth(50);

        updatePayloadsTable();

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JButton manageCategoryButton = new JButton("Manage Category");
        manageCategoryButton.addActionListener(e -> {
            CategoryManagerDialog dialog = new CategoryManagerDialog( panel, categoryStorage, payloadStorage);
            dialog.setModal(true);
            dialog.setVisible(true);

            updatePayloadsTable();
        });

        JButton addButton = new JButton("Add Payload");
        addButton.addActionListener(this::addPayload);

        JButton editButton = new JButton("Edit Payload");
        editButton.addActionListener(this::editPayload);

        JButton deleteButton = new JButton("Delete Payload");
        deleteButton.addActionListener(this::deletePayload);

        JButton importButton = new JButton("Import as JSON");
        importButton.addActionListener(this::importPayload);

        JButton exportButton = new JButton("Export as JSON");
        exportButton.addActionListener(this::exportPayload);

        buttonPanel.add(Box.createVerticalStrut(20));
        buttonPanel.add(manageCategoryButton);
        buttonPanel.add(Box.createVerticalStrut(40));

        buttonPanel.add(addButton);
        buttonPanel.add(Box.createVerticalStrut(10));
        buttonPanel.add(editButton);
        buttonPanel.add(Box.createVerticalStrut(10));
        buttonPanel.add(deleteButton);

        JPanel bottomButtonPanel = new JPanel();
        bottomButtonPanel.setLayout(new BoxLayout(bottomButtonPanel, BoxLayout.Y_AXIS));

        bottomButtonPanel.setBorder(BorderFactory.createEmptyBorder(50, 10, 10, 10));
        bottomButtonPanel.add(importButton);
        bottomButtonPanel.add(Box.createVerticalStrut(10));
        bottomButtonPanel.add(exportButton);

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(buttonPanel, BorderLayout.NORTH);
        leftPanel.add(bottomButtonPanel, BorderLayout.SOUTH);

        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0.2;
        gbc.weighty = 1;
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.anchor = GridBagConstraints.SOUTHWEST;
        mainPanel.add(leftPanel, gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.8;
        gbc.fill = GridBagConstraints.BOTH;
        mainPanel.add(new JScrollPane(payloadTable), gbc);

        panel.add(mainPanel, BorderLayout.CENTER);
    }

    public JPanel getPanel() {
        return panel;
    }

    private void deletePayload(ActionEvent e) {
        int selectedRow = payloadTable.getSelectedRow();
        if (selectedRow >= 0) {
            int confirm = JOptionPane.showConfirmDialog(panel, "Delete selected payload?", "Confirm", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                payloadStorage.deletePayloadAt(selectedRow);
                updatePayloadsTable();
            }
        } else {
            JOptionPane.showMessageDialog(panel, "Please select a payload to delete!", "Warning", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void addPayload(ActionEvent e) {
        List<Category> categories = categoryStorage.getCategories();
        JComboBox<String> categoryComboBox = new JComboBox<>();
        categoryComboBox.addItem("-- Select Category --");

        for (Category cat : categories) {
            categoryComboBox.addItem(cat.category());
        }

        JTextArea textAreaName = new JTextArea(1, 50);
        JScrollPane scrollPaneName = new JScrollPane(textAreaName);
        scrollPaneName.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextArea textAreaPayload = new JTextArea(7, 50);
        JScrollPane scrollPanePayload = new JScrollPane(textAreaPayload);
        scrollPanePayload.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.Y_AXIS));

        JLabel categoryLabel = new JLabel("Category:");
        categoryLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        categoryComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel nameLabel = new JLabel("Name:");
        nameLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel payloadLabel = new JLabel("Payload*:");
        payloadLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        inputPanel.add(categoryLabel);
        inputPanel.add(categoryComboBox);
        inputPanel.add(Box.createVerticalStrut(10));

        inputPanel.add(nameLabel);
        inputPanel.add(scrollPaneName);
        inputPanel.add(Box.createVerticalStrut(10));

        inputPanel.add(payloadLabel);
        inputPanel.add(scrollPanePayload);

        int result = JOptionPane.showConfirmDialog(panel, inputPanel, "Enter new payload",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String name = textAreaName.getText().trim();
            String payload = textAreaPayload.getText().trim();
            String selectedCategory = (String) categoryComboBox.getSelectedItem();

            if (payload.isEmpty()) {
                JOptionPane.showMessageDialog(null, "Payload cannot be empty.", "Warning", JOptionPane.WARNING_MESSAGE);
                return;
            }

            Payload newPayload = new Payload(name, payload, new Category(selectedCategory));
            if (payloadStorage.getPayloads().contains(newPayload)) {
                JOptionPane.showMessageDialog(null, "Payload already exists", "Error", JOptionPane.ERROR_MESSAGE);
            } else {
                payloadStorage.addPayload(newPayload);
                updatePayloadsTable();
            }
        }
    }

    private void editPayload(ActionEvent e) {
        int selectedRow = payloadTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(panel, "Please select a payload to edit!", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        Payload oldPayload = payloadStorage.getPayloads().get(selectedRow);

        JTextArea textAreaName = new JTextArea(1, 50);
        textAreaName.setText(oldPayload.name());
        JScrollPane scrollPaneName = new JScrollPane(textAreaName);
        scrollPaneName.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextArea textAreaPayload = new JTextArea(6, 50);
        textAreaPayload.setText(oldPayload.payload());
        JScrollPane scrollPanePayload = new JScrollPane(textAreaPayload);
        scrollPanePayload.setAlignmentX(Component.LEFT_ALIGNMENT);

        JComboBox<String> categoryComboBox = new JComboBox<>();
        categoryComboBox.addItem("-- Select Category --");
        for (Category cat : categoryStorage.getCategories()) {
            categoryComboBox.addItem(cat.category());
        }

        categoryComboBox.setSelectedItem(oldPayload.category().category());
        categoryComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.Y_AXIS));

        inputPanel.add(new JLabel("Category:"));
        inputPanel.add(categoryComboBox);
        inputPanel.add(Box.createVerticalStrut(10));

        inputPanel.add(new JLabel("Name:"));
        inputPanel.add(scrollPaneName);
        inputPanel.add(Box.createVerticalStrut(10));

        inputPanel.add(new JLabel("Payload*:"));
        inputPanel.add(scrollPanePayload);

        int result = JOptionPane.showConfirmDialog(panel, inputPanel, "Edit payload",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String newName = textAreaName.getText().trim();
            String newPayload = textAreaPayload.getText().trim();
            String newCategory = (String) categoryComboBox.getSelectedItem();

            if (newPayload.isEmpty()) {
                JOptionPane.showMessageDialog(panel, "Payload cannot be empty!", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            Payload updatedPayload = new Payload(newName, newPayload, new Category(newCategory));
            payloadStorage.updatePayloadAt(selectedRow, updatedPayload);
            updatePayloadsTable();
        }
    }

    private void updatePayloadsTable() {
        tableModel.setRowCount(0);
        List<Payload> payloads = payloadStorage.getPayloads();
        for (int i = 0; i < payloads.size(); i++) {
            tableModel.addRow(new Object[]{i + 1, payloads.get(i).name(), payloads.get(i).payload(), payloads.get(i).category()});
        }
    }

    private void exportPayload(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showSaveDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            if (!file.getName().toLowerCase().endsWith(".json")) {
                file = new File(file.getAbsolutePath() + ".json");
            }

            try (FileWriter writer = new FileWriter(file, StandardCharsets.UTF_8)) {
                List<Payload> payloadList = payloadStorage.getPayloads();

                if (payloadList == null || payloadList.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "No payloads to export!", "Warning", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                Gson gson = new Gson();
                String json = gson.toJson(payloadList);
                writer.write(json);

                JOptionPane.showMessageDialog(null, "Payloads exported successfully to: " + file.getAbsolutePath());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null, "Error exporting payloads: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importPayload(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                String content = Files.readString(file.toPath(), StandardCharsets.UTF_8).trim();

                if (content.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "File is empty", "Warning", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                Gson gson = new Gson();
                Type listType = new TypeToken<List<Payload>>() {}.getType();
                List<Payload> importedPayloads = gson.fromJson(content, listType);

                for (Payload newPayload : importedPayloads) {
                    if (!payloadStorage.getPayloads().contains(newPayload)) {
                        payloadStorage.addPayload(newPayload);
                    }

                    if (!categoryStorage.getCategories().contains(newPayload.category())) {
                        categoryStorage.addCategory(newPayload.category());
                    }
                }

                updatePayloadsTable();
                JOptionPane.showMessageDialog(null, "Payloads imported successfully");
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null, "Error importing payloads: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }


    @Override
    public String getTabCaption() {
        return "Payloads Manager";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }
}
