package models;

import java.util.*;

public class ContactList {

    public List<Contact> getContactList() {
        return this.contactList;
    }

    public void setContactList(List<Contact> contactList) {
        this.contactList = contactList;
    }

    private List<Contact> contactList;

}

