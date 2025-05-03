package storage;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import model.Category;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CategoryStorage {
    private static final String STORAGE_KEY = "category_db";

    private final IBurpExtenderCallbacks iBurpExtenderCallbacks;
    private final List<Category> categories;

    public CategoryStorage(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.iBurpExtenderCallbacks = iBurpExtenderCallbacks;
        this.categories = loadCategories();
    }

    public List<Category> getCategories() {
        return Collections.unmodifiableList(categories);
    }

    public void addCategory(Category category) {
        if (category == null || category.category().isEmpty()) return;
        if (!categories.contains(category)) {
            categories.add(category);
            saveCategories();
        }
    }

    public void deleteCategoryAt(int index) {
        if (index >= 0 && index < categories.size()) {
            categories.remove(index);
            saveCategories();
        }
    }

    public void updateCategoryAt(int index, Category newCategory) {
        if (newCategory == null || newCategory.category().isEmpty()) return;
        if (index >= 0 && index < categories.size()) {
            categories.set(index, newCategory);
            saveCategories();
        }
    }

    private void saveCategories() {
        Gson gson = new Gson();
        String json = gson.toJson(categories);
        iBurpExtenderCallbacks.saveExtensionSetting(STORAGE_KEY, json);
    }

    private List<Category> loadCategories() {
        String json = iBurpExtenderCallbacks.loadExtensionSetting(STORAGE_KEY);
        if (json == null || json.isEmpty()) {
            return new ArrayList<>();
        }

        Gson gson = new Gson();
        Type listType = new TypeToken<List<Category>>() {}.getType();
        try {
            return gson.fromJson(json, listType);
        } catch (JsonSyntaxException e) {
            return new ArrayList<>();
        }
    }

}
