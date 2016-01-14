package models;

public class User {
    public void setEmail(String email) {
        this.email = email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public String getUuid() {
        return uuid;
    }

    private String uuid;
    private String email;
    private String password;

    public User(String email, String password) {
        this.uuid = java.util.UUID.randomUUID().toString();
        this.email = email;
        this.password = password;
    }

}

