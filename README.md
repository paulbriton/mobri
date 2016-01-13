MobRI
=====

This project calls Twitter and Google API in order to get user contact list with java [Play Framework](https://playframework.com/)

Installation
------------

Clone the repo and run the following command:

    activator ui

You need to provide valid credentials for APIs calls. Please refer to https://apps.twitter.com/ and https://console.developers.google.com/ in order to manage apps.

Then create a twitter.json file as the following:

    {
        "key": "yourkey",
        "secret": "yoursecret"
    }
    
Or specify them by environment variables which should be called PROVIDER_KEY and PROVIDER_SECRET where the provider is either GOOGLE or TWITTER

The authorized callbacks url should be: http://www.example.com/providerCallback