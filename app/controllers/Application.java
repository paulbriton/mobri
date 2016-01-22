package controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Strings;
import play.Play;
import play.libs.F.Option;
import play.libs.F.Promise;
import play.libs.Json;
import play.libs.oauth.OAuth;
import play.libs.oauth.OAuth.ConsumerKey;
import play.libs.oauth.OAuth.OAuthCalculator;
import play.libs.oauth.OAuth.RequestToken;
import play.libs.oauth.OAuth.ServiceInfo;
import play.libs.ws.WSAuthScheme;
import play.libs.ws.WSClient;
import play.libs.ws.WSRequest;
import play.mvc.Controller;
import play.mvc.Result;
import views.html.index;
import java.util.Iterator;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Application extends Controller {

    static final String GOOGLE_KEY = getKey("google");
    static final String GOOGLE_SECRET = getSecret("google");

    static final String TWITTER_KEY = getKey("twitter");
    static final String TWITTER_SECRET = getSecret("twitter");

    static final ConsumerKey TWITTER_CONS = new ConsumerKey(TWITTER_KEY, TWITTER_SECRET);
    private static final ServiceInfo SERVICE_INFO = new ServiceInfo(
            "https://api.twitter.com/oauth/request_token",
            "https://api.twitter.com/oauth/access_token",
            "https://api.twitter.com/oauth/authorize",
            TWITTER_CONS
    );
    private static final OAuth TWITTER = new OAuth(SERVICE_INFO, false);

    private final WSClient ws;

    @Inject
    public Application(WSClient ws) {
        this.ws = ws;
    }

    public Result index() {
        return ok(index.render("Your new application is ready."));
    }

    public Promise<Result> twitterAppOnly() {
        //OAuth2 test with twitter API
        WSRequest request = ws.url("https://api.twitter.com/oauth2/token")
                .setAuth(TWITTER_KEY, TWITTER_SECRET, WSAuthScheme.BASIC);
        WSRequest complexRequest = request.setHeader("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8.")
                .setQueryParameter("grant_type", "client_credentials");
        JsonNode json = Json.newObject();
        return complexRequest.post(json).map(response ->
            ok(response.asJson())
        );
    }

    public Result googleAuth() {
        if (Strings.isNullOrEmpty(session("credentials"))) {
            // Redirect user to the google auth page
            String url = "https://accounts.google.com/o/oauth2/v2/auth";
            url += "?response_type=code";
            url += "&client_id=" + GOOGLE_KEY;
            url += "&redirect_uri=" + routes.Application.googleCallback().absoluteURL(request());
            url += "&scope=https://www.googleapis.com/auth/plus.login";
            return redirect(url);
        }
        else {
            return redirect(routes.Application.googleCallback());
        }
    }

    // @TODO Use a refresh token
    public Promise<Result> googleCallback() {
        // Get the response code in the queryString
        String code = request().getQueryString("code");
        // Check if access token is already in session
        if (Strings.isNullOrEmpty(session("credentials")) && !Strings.isNullOrEmpty(code)) {
            String url = "https://www.googleapis.com/oauth2/v4/token";
            String redirectUri = routes.Application.googleCallback().absoluteURL(request());
            // Access token request
            return ws.url(url).setContentType("application/x-www-form-urlencoded")
                    .post("code=" + code +
                            "&client_id=" + GOOGLE_KEY +
                            "&client_secret=" + GOOGLE_SECRET +
                            "&redirect_uri=" + redirectUri +
                            "&grant_type=authorization_code")
                    .map(response -> {
                        String json = response.asJson().toString();
                        if (!Strings.isNullOrEmpty(json)) {
                            // Store credentials in session
                            session("credentials", json);
                        }
                        return redirect(routes.Application.googleCallback());
                    });
        }
        else {
            // Access token already get, make API request with it
            JsonNode json = Json.parse(session("credentials"));
            String getUrl = "https://www.googleapis.com/plus/v1/people/me/people/connected?access_token="+json.path("access_token").asText();
            return ws.url(getUrl).get().map(
                    response -> {
                        JsonNode jsonRes = response.asJson();
                        System.out.println(jsonRes.toString());
                        if (Strings.isNullOrEmpty(jsonRes.path("error").path("message").toString())) {
                            return redirect(routes.Application.index());
                        }
                        else {
                            session().clear();
                            return redirect(routes.Application.googleAuth());
                        }
                    }
            );
        }
    }

    public Result twitterAuth() {
        // OAuth 1 twitter auth handler
        String verifier = request().getQueryString("oauth_verifier");
        if (Strings.isNullOrEmpty(verifier)) {
            String url = routes.Application.twitterAuth().absoluteURL(request());
            RequestToken requestToken = TWITTER.retrieveRequestToken(url);
            saveSessionTokenPair(requestToken);
            return redirect(TWITTER.redirectUrl(requestToken.token));
        } else {
            RequestToken requestToken = getSessionTokenPair().get();
            RequestToken accessToken = TWITTER.retrieveAccessToken(requestToken, verifier);
            saveSessionTokenPair(accessToken);
            return redirect(routes.Application.twitterCallback());
        }
    }

    public Promise<Result> twitterCallback() {
        Option<RequestToken> sessionTokenPair = getSessionTokenPair();
        if (sessionTokenPair.isDefined()) {
            return ws.url("https://api.twitter.com/1.1/friends/ids.json")
                    .sign(new OAuthCalculator(TWITTER_CONS, sessionTokenPair.get()))
                    .get()
                    .map(response -> {
                        String ids = response.asJson().path("ids").toString();
                        ids = ids.replace("[","");
                        ids = ids.replace("]","");
                        session("ids", ids);
                        return redirect(routes.Application.twitterFriends());
                    });
        }
        return Promise.pure(redirect(routes.Application.twitterAuth()));
    }

    public Promise<Result> twitterFriends() {
        Option<RequestToken> sessionTokenPair = getSessionTokenPair();
        String ids = session("ids");
        System.out.println(ids);
        return ws.url("https://api.twitter.com/1.1/users/lookup.json?user_id=338985020")//+ids)
                .sign(new OAuthCalculator(TWITTER_CONS, sessionTokenPair.get()))
                .get()
                .map(response -> {
                    JsonNode respJson = response.asJson();
                    System.out.println(respJson);
                    Iterator<JsonNode> jsonIterator = respJson.elements();
                    String name = "";
                    String location = "";
                    while (jsonIterator.hasNext()) {
                        JsonNode j = jsonIterator.next();
                        name = j.path("name").toString();
                        location = j.path("location").toString();
                    }
                    JsonNode json = Json.newObject()
                        .put("name", name)
                        .put("location", location);
                    ws.url("http://localhost:9200/friends/test/").post(json);
                    return ok(index.render(respJson.toString()));
                });
    }

    public Result deleteContacts() {
        ws.url("http://localhost:9200/friends/").delete();
        return ok(index.render("Your new application is ready."));
    }

    private void saveSessionTokenPair(RequestToken requestToken) {
        session("token", requestToken.token);
        session("secret", requestToken.secret);
    }

    private Option<RequestToken> getSessionTokenPair() {
        if (session().containsKey("token")) {
            return Option.Some(new RequestToken(session("token"), session("secret")));
        }
        return Option.None();
    }

    private static String getKey(String file)  {
        String env = file.toUpperCase() + "_KEY";

        //Check environment variable
        if (System.getenv(env) != null) {
            return System.getenv(env);
        }
        // Else key is in environment variable, return it
        else {
            //If null read file.json
            return processJson(file, "key");
        }
    }

    private static String getSecret(String file) {
        String env = file.toUpperCase() + "_SECRET";
        if (System.getenv(env) != null) {
            return System.getenv(env);
        }
        else {
            return processJson(file, "secret");
        }
    }

    private static String processJson(String file, String val) {
        try {
            byte[] encoded = Files.readAllBytes(Paths.get(Play.application().path() + "/"+file+".json"));
            String credentials = new String(encoded, "UTF-8");
            JsonNode json = Json.parse(credentials);
            return json.path(val).asText();
        }
        catch (IOException e) {
            System.err.println("Caught IOException: " + e.getMessage());
        }
        return null;
    }
}
