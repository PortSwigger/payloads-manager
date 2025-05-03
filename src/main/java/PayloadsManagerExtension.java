import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import storage.CategoryStorage;
import storage.PayloadStorage;

public class PayloadsManagerExtension implements IBurpExtender{
    private PayloadStorage payloadStorage;
    private CategoryStorage categoryStorage;
    private final String extensionName = "Payloads Manager";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        iBurpExtenderCallbacks.setExtensionName(extensionName);
        iBurpExtenderCallbacks.printOutput(extensionName + " loaded");

        this.payloadStorage = new PayloadStorage(iBurpExtenderCallbacks);
        this.categoryStorage = new CategoryStorage(iBurpExtenderCallbacks);

        iBurpExtenderCallbacks.addSuiteTab(new PayloadsManagerTab(payloadStorage, categoryStorage));
        iBurpExtenderCallbacks.registerContextMenuFactory(new PayloadsManagerMenu(payloadStorage, categoryStorage));
    }
}
