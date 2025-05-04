import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import model.Category;
import model.Payload;
import org.apache.commons.lang3.ArrayUtils;
import storage.CategoryStorage;
import storage.PayloadStorage;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;


public class PayloadsManagerMenu implements IContextMenuFactory {
    private final PayloadStorage payloadStorage;
    private final CategoryStorage categoryStorage;
    private IContextMenuInvocation currentInvocation;
    private PayloadsManagerTab payloadsManagerTab;

    public PayloadsManagerMenu(PayloadsManagerTab payloadsManagerTab, PayloadStorage payloadStorage, CategoryStorage categoryStorage) {
        this.payloadStorage = payloadStorage;
        this.categoryStorage = categoryStorage;
        this.payloadsManagerTab = payloadsManagerTab;
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
                invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE) {
            currentInvocation = invocation;

            List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
            JMenu subMenu = new JMenu("Payloads Manager");
            
            JMenuItem menuItemDefault = new JMenuItem("Add to Payloads Manager");
            subMenu.add(menuItemDefault);
            menuItemDefault.addActionListener((ActionEvent e) -> {
                addToPayloadManager();
            });

            subMenu.addSeparator();

            List<Category> categories = new ArrayList<>(categoryStorage.getCategories());
            List<Payload> payloadUncategorized = new ArrayList<>(payloadStorage.getUncategorizedPayloads());

            if (categories.isEmpty() && payloadUncategorized.isEmpty()) {
                JMenuItem noNotesItem = new JMenuItem("No payloads available");
                noNotesItem.setEnabled(false);
                subMenu.add(noNotesItem);
            } else {
                if (!categories.isEmpty()) {
                    categories.sort(Comparator.comparing(Category::category));
                    for (Category category : categories) {
                        JMenu subCatMenu = new JMenu(category.category());
                        List<Payload> payloadByCategory = new ArrayList<>(payloadStorage.getPayloadsByCategory(category.category()));
                        if (payloadByCategory.isEmpty()) {
                            JMenuItem noNotesItem = new JMenuItem("No payloads available");
                            noNotesItem.setEnabled(false);
                            subCatMenu.add(noNotesItem);
                        } else {
                            payloadByCategory.sort(Comparator.comparing(Payload::name));

                            for (Payload payload : payloadByCategory) {
                                String nameText = payload.name();
                                String payloadText = payload.payload();
                                String displayText;

                                if(nameText.isEmpty()){
                                    displayText = payloadText.length() > 50 ? payloadText.substring(0, 50) : payloadText;
                                }else{
                                    displayText = nameText.length() > 50 ? nameText.substring(0, 50) : nameText;
                                }

                                JMenuItem menuItem = new JMenuItem(displayText);
                                menuItem.addActionListener((ActionEvent e) -> {
                                    insertPayload(payload);
                                });
                                subCatMenu.add(menuItem);
                            }
                        }
                        subMenu.add(subCatMenu);
                    }
                }

                if (!payloadUncategorized.isEmpty()) {
                    payloadUncategorized.sort(Comparator.comparing(Payload::name));

                    for (Payload payload : payloadUncategorized) {

                        String nameText = payload.name();
                        String payloadText = payload.payload();
                        String displayText;

                        if(nameText.isEmpty()){
                            displayText = payloadText.length() > 50 ? payloadText.substring(0, 50) : payloadText;
                        }else{
                            displayText = nameText.length() > 50 ? nameText.substring(0, 50) : nameText;
                        }

                        JMenuItem menuItem = new JMenuItem(displayText);
                        menuItem.addActionListener((ActionEvent e) -> {
                            insertPayload(payload);
                        });
                        subMenu.add(menuItem);
                    }
                }
            }

            menuItems.add(subMenu);
            return menuItems;

        } else {
            return null;
        }
    }

    private void insertPayload(Payload payload) {
        IHttpRequestResponse[] selectedItems = currentInvocation.getSelectedMessages();
        int[] selectedBounds = currentInvocation.getSelectionBounds();
        byte selectedInvocationContext = currentInvocation.getInvocationContext();

        if (selectedItems != null && selectedItems.length > 0 && selectedBounds.length == 2) {
            byte[] selectedRequestOrResponse;
            if (selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
                selectedRequestOrResponse = selectedItems[0].getRequest();
            } else {
                selectedRequestOrResponse = selectedItems[0].getResponse();
            }

            byte[] preSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, 0, selectedBounds[0]);
            byte[] postSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[1], selectedRequestOrResponse.length);

            byte[] newRequestResponseBytes = ArrayUtils.addAll(preSelectedPortion, payload.toString().getBytes());
            newRequestResponseBytes = ArrayUtils.addAll(newRequestResponseBytes, postSelectedPortion);

            if (selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
                selectedItems[0].setRequest(newRequestResponseBytes);
            } else {
                selectedItems[0].setResponse(newRequestResponseBytes);
            }
        } else {
            JOptionPane.showMessageDialog(null, "Invalid selection, please try again.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }


    private void addToPayloadManager() {
        IHttpRequestResponse[] selectedItems = currentInvocation.getSelectedMessages();
        int[] selectedBounds = currentInvocation.getSelectionBounds();

        if (selectedItems != null && selectedItems.length > 0 && selectedBounds != null && selectedBounds.length == 2) {
            byte[] requestOrResponse;
            if (currentInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
                requestOrResponse = selectedItems[0].getRequest();
            } else {
                requestOrResponse = selectedItems[0].getResponse();
            }

            byte[] selectedBytes = Arrays.copyOfRange(requestOrResponse, selectedBounds[0], selectedBounds[1]);
            String selectedText = new String(selectedBytes).trim();

            if (selectedText.isEmpty()) {
                JOptionPane.showMessageDialog(null, "No text selected.", "Warning", JOptionPane.WARNING_MESSAGE);
                return;
            }

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
            textAreaPayload.setText(selectedText);
            JScrollPane scrollPanePayload = new JScrollPane(textAreaPayload);
            scrollPanePayload.setAlignmentX(Component.LEFT_ALIGNMENT);

            JPanel inputPanel = new JPanel();
            inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.Y_AXIS));

            JLabel categoryLabel = new JLabel("Category:");
            categoryLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
            categoryComboBox.setAlignmentX(Component.LEFT_ALIGNMENT);

            JLabel nameLabel = new JLabel("Payload Name:");
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

            int result = JOptionPane.showConfirmDialog(null, inputPanel, "Add to Payloads Manager",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

            if (result == JOptionPane.OK_OPTION) {
                String name = textAreaName.getText().trim();
                String payload = textAreaPayload.getText().trim();
                String selectedCategory = (String) categoryComboBox.getSelectedItem();

                if (payload.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Payload cannot be empty.", "Warning", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                Category category = new Category(selectedCategory != null ? selectedCategory : "");
                Payload newPayload = new Payload(name, payload, category);

                if (payloadStorage.getPayloads().contains(newPayload)) {
                    JOptionPane.showMessageDialog(null, "Payload already exists.", "Error", JOptionPane.ERROR_MESSAGE);
                } else {
                    payloadStorage.addPayload(newPayload);
                    payloadsManagerTab.refreshTable();

                    JOptionPane.showMessageDialog(null, "Payload added successfully.", "Success", JOptionPane.INFORMATION_MESSAGE);
                }
            }

        } else {
            JOptionPane.showMessageDialog(null, "Invalid selection, please try again.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

}
