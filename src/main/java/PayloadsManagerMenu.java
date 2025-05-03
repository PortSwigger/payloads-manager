import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import model.Category;
import model.Payload;
import org.apache.commons.lang3.ArrayUtils;
import storage.CategoryStorage;
import storage.PayloadStorage;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;


public class PayloadsManagerMenu implements IContextMenuFactory {
    private final PayloadStorage payloadStorage;
    private final CategoryStorage categoryStorage;
    private IContextMenuInvocation currentInvocation;

    public PayloadsManagerMenu(PayloadStorage payloadStorage, CategoryStorage categoryStorage) {
        this.payloadStorage = payloadStorage;
        this.categoryStorage = categoryStorage;
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
                invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE) {
            currentInvocation = invocation;

            List<JMenuItem> menuItems = new ArrayList<>();
            List<Category> categories = new ArrayList<>(categoryStorage.getCategories());
            List<Payload> payloadUncategorized = new ArrayList<>(payloadStorage.getUncategorizedPayloads());

            if (categories.isEmpty() && payloadUncategorized.isEmpty()) {
                JMenuItem noNotesItem = new JMenuItem("No payloads available");
                noNotesItem.setEnabled(false);
                menuItems.add(noNotesItem);
            } else {
                if (!categories.isEmpty()) {
                    categories.sort(Comparator.comparing(Category::category));
                    for (Category category : categories) {
                        JMenu subMenu = new JMenu(category.category());
                        List<Payload> payloadByCategory = new ArrayList<>(payloadStorage.getPayloadsByCategory(category.category()));
                        if (payloadByCategory.isEmpty()) {
                            JMenuItem noNotesItem = new JMenuItem("No payloads available");
                            noNotesItem.setEnabled(false);
                            subMenu.add(noNotesItem);
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
                                subMenu.add(menuItem);
                            }
                        }
                        menuItems.add(subMenu);
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
                        menuItems.add(menuItem);
                    }
                }
            }

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
}
