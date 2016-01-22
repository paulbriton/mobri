MobRI
=====

This project calls Twitter and Google API in order to get user contact list with java [Play Framework v2.4](https://playframework.com/) and index them with [Elasticsearch v2.1](https://www.elastic.co/)

Installation
------------

You need to provide valid credentials for APIs calls. Please refer to https://apps.twitter.com/ and https://console.developers.google.com/ in order to manage apps.

Then specify them by environment variables which should be called PROVIDER_KEY and PROVIDER_SECRET where the provider is either GOOGLE or TWITTER, or create a twitter.json file as the following:

    {
        "key": "yourkey",
        "secret": "yoursecret"
    }
    
You also need to set authorized callbacks url like: http://www.example.com/providerCallback

Next, download Elasticsearch and start the node as described [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/_installation.html)

Finally clone the repo and run the following command:

    activator ui