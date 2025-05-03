package storage;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import model.Category;
import model.Payload;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class PayloadStorage {
    private static final String STORAGE_KEY = "payload_db";

    private final IBurpExtenderCallbacks iBurpExtenderCallbacks;
    private final List<Payload> payloads;

    public PayloadStorage(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
        this.payloads = loadPayloads();
    }

    public List<Payload> getPayloads() {
        return Collections.unmodifiableList(payloads);
    }

    public List<Payload> getPayloadsByCategory(String category) {
        return payloads.stream()
                .filter(payload -> payload.category().category().equals(category))
                .collect(Collectors.toList());
    }

    public List<Payload> getUncategorizedPayloads() {
        return payloads.stream()
                .filter(payload -> payload.category().category().isEmpty())
                .collect(Collectors.toList());
    }

    public void addPayload(Payload payload) {
        if (payload == null || payload.payload().isEmpty()) return;

        String name = payload.name();
        if (name == null || name.trim().isEmpty()) {
            name = "";
        }

        Category category = payload.category();
        String categoryValue = (category != null && category.category() != null) ? category.category() : "";
        if (categoryValue.trim().isEmpty() || categoryValue.equals("-- Select Category --")) {
            category = new Category("");
        }

        Payload newPayload = new Payload(name, payload.payload(), category);

        if (!payloads.contains(newPayload)) {
            payloads.add(newPayload);
            savePayloads();
        }
    }

    public void deletePayloadAt(int index) {
        if (index >= 0 && index < payloads.size()) {
            payloads.remove(index);
            savePayloads();
        }
    }

    public void updatePayloadAt(int index, Payload newPayload) {
        if (newPayload == null || newPayload.payload().isEmpty()) return;

        String name = newPayload.name();
        if (name == null || name.trim().isEmpty()) {
            name = "";
        }

        Category category = newPayload.category();
        String categoryValue = (category != null && category.category() != null) ? category.category() : "";
        if (categoryValue.trim().isEmpty() || categoryValue.equals("-- Select Category --")) {
            category = new Category("");
        }

        Payload updatedPayload = new Payload(name, newPayload.payload(), category);

        if (index >= 0 && index < payloads.size()) {
            payloads.set(index, updatedPayload);
            savePayloads();
        }
    }

    private void savePayloads() {
            Gson gson = new Gson();
            String json = gson.toJson(payloads);
            iBurpExtenderCallbacks.saveExtensionSetting(STORAGE_KEY, json);
    }

    private List<Payload> loadPayloads() {
        String json = iBurpExtenderCallbacks.loadExtensionSetting(STORAGE_KEY);
        if (json == null || json.isEmpty()) {
            return new ArrayList<>();
        }

        Gson gson = new Gson();
        Type payloadListType = new TypeToken<List<Payload>>() {}.getType();
        try {
            return gson.fromJson(json, payloadListType);
        } catch (JsonSyntaxException e) {
            return new ArrayList<>();
        }
    }


    public void updatePayloadCategory(String oldCategory, String newCategory) {
        boolean changed = false;

        for (int i = 0; i < payloads.size(); i++) {
            Payload payload = payloads.get(i);
            if (payload.category().category().equals(oldCategory)) {
                Payload updated = new Payload(payload.name(), payload.payload(), new Category(newCategory));
                payloads.set(i, updated);
                changed = true;
            }
        }

        if (changed) {
            savePayloads();
        }
    }
}