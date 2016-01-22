package models;

public class Contact {
    public void setName(String name) {
        this.name = name;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getName() {
        return this.name;
    }

    public String getLocation() {
        return this.location;
    }

    private String name;
    private String location;

    public Contact() {
        this.name = "";
        this.location = "";
    }

    public Contact(String name, String location) {
        this.name = name;
        this.location = location;
    }

}

