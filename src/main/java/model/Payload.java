package model;

import java.util.Objects;

public record Payload(String name, String payload, Category category) {
    @Override
    public String toString() {
        return payload;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Payload payload = (Payload) obj;
        return Objects.equals(this.payload, payload.payload);
    }
}
