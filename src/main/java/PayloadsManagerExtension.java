import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import storage.CategoryStorage;
import storage.PayloadStorage;

public class PayloadsManagerExtension implements IBurpExtender{
    private PayloadStorage payloadStorage;
    private CategoryStorage categoryStorage;
    private final String extensionName = "Payloads Manager";
    private  PayloadsManagerTab payloadsManagerTab;



    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        iBurpExtenderCallbacks.setExtensionName(extensionName);
        iBurpExtenderCallbacks.printOutput(extensionName + " loaded");

        this.payloadStorage = new PayloadStorage(iBurpExtenderCallbacks);
        this.categoryStorage = new CategoryStorage(iBurpExtenderCallbacks);
        this.payloadsManagerTab = new PayloadsManagerTab(payloadStorage, categoryStorage);

        iBurpExtenderCallbacks.addSuiteTab(payloadsManagerTab);
        iBurpExtenderCallbacks.registerContextMenuFactory(new PayloadsManagerMenu(payloadsManagerTab, payloadStorage, categoryStorage));
    }
}
