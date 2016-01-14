package models;

public class User {
    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getFirstname() {

        return firstname;
    }

    public String getLastname() {
        return lastname;
    }

    private String uuid;
    private String firstname;
    private String lastname;

    public User(String firstname, String lastname) {
        this.uuid = java.util.UUID.randomUUID().toString();
        this.firstname = firstname;
        this.lastname = lastname;
    }

}

