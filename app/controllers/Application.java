package controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Strings;
import play.Play;
import play.libs.F.Option;
import play.libs.F.Promise;
import play.libs.Json;
import play.libs.oauth.OAuth;
import play.libs.oauth.OAuth.ConsumerKey;
import play.libs.oauth.OAuth.RequestToken;
import play.libs.oauth.OAuth.ServiceInfo;
import play.libs.ws.WSAuthScheme;
import play.libs.ws.WSClient;
import play.libs.ws.WSRequest;
import play.mvc.Controller;
import play.mvc.Result;
import views.html.index;

import javax.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Application extends Controller {

    static final ConsumerKey TWITTER_KEY = new ConsumerKey(getKey("twitter"), getSecret("twitter"));

    private static final ServiceInfo SERVICE_INFO = new ServiceInfo(
            "https://api.twitter.com/oauth/request_token",
            "https://api.twitter.com/oauth/access_token",
            "https://api.twitter.com/oauth/authorize",
            TWITTER_KEY
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

    public Result test() {
        return ok(index.render("HELLO"));
    }

    public Promise<Result> twitterAppOnly() {
        //OAuth2
        WSRequest request = ws.url("https://api.twitter.com/oauth2/token")
                .setAuth(getKey("twitter"), getSecret("twitter"), WSAuthScheme.BASIC);
        WSRequest complexRequest = request.setHeader("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8.");
        JsonNode json = Json.newObject().put("grant_type", "client_credentials");

        return complexRequest.post(json).map(response ->
            ok(response.asJson())
        );
    }

    public Result googleAuth() {
        WSRequest request = ws.url("https://accounts.google.com/o/oauth2/v2/auth");
        return ok(index.render("toto"));
    }

    public Result twitterAuth() {
        String verifier = request().getQueryString("oauth_verifier");
        if (Strings.isNullOrEmpty(verifier)) {
            String url = routes.Application.auth().absoluteURL(request());
            RequestToken requestToken = TWITTER.retrieveRequestToken(url);
            saveSessionTokenPair(requestToken);
            return redirect(TWITTER.redirectUrl(requestToken.token));
        } else {
            RequestToken requestToken = getSessionTokenPair().get();
            RequestToken accessToken = TWITTER.retrieveAccessToken(requestToken, verifier);
            saveSessionTokenPair(accessToken);
            return redirect(routes.Application.index());
        }
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
        try {
            byte[] encoded = Files.readAllBytes(Paths.get(Play.application().path()+"/"+file+".json"));
            String credentials = new String(encoded, "UTF-8");
            JsonNode json = Json.parse(credentials);
            return json.path("key").asText();
        }
        catch (IOException e) {
            System.err.println("Caught IOException: " + e.getMessage());
        }
        return "";
    }

    private static String getSecret(String file) {
        try {
            byte[] encoded = Files.readAllBytes(Paths.get(Play.application().path() + "/"+file+".json"));
            String credentials = new String(encoded, "UTF-8");
            JsonNode json = Json.parse(credentials);
            return json.path("secret").asText();
        }
        catch (IOException e) {
            System.err.println("Caught IOException: " + e.getMessage());
        }
        return "";
    }
}
