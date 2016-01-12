package controllers;

import com.fasterxml.jackson.databind.JsonNode;
import play.libs.F.Promise;
import play.libs.Json;
import play.libs.ws.WSAuthScheme;
import play.libs.ws.WSClient;
import play.libs.ws.WSRequest;
import play.mvc.Controller;
import play.mvc.Result;
import views.html.index;

import javax.inject.Inject;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Application extends Controller {

    public Result index() {
        return ok(index.render("Your new application is ready."));
    }

    public Result test() {
        return ok(index.render("HELLO"));
    }

    @Inject WSClient ws;
    public Promise<Result> sendReq() {
        String jsonTwitter = "";
        try {
            byte[] encoded = Files.readAllBytes(Paths.get("../../twitter.json"));
            jsonTwitter = new String(encoded, "UTF-8");
        }
        catch (Exception e) {
            System.err.println("Caught IOException: " + e.getMessage());
        }

        System.out.println(jsonTwitter);
        //WSRequest request = ws.url("https://api.twitter.com/oauth2/token").setAuth(authKey, authSecret, WSAuthScheme.BASIC);
        //WSRequest complexRequest = request.setHeader("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8.")
        //        .setQueryParameter("grant_type", "client_credentials");
        //JsonNode json = Json.newObject().put("grant_type", "client_credentials");
        //return complexRequest.post(json).map(response ->
        //    ok(response.asJson())
        //);

        //Promise<WSResponse> responsePromise = complexRequest.setFollowRedirects(true).post("granttype");
        /*return responsePromise.map(response ->
                ok("Feed title: " + response.asJson().findPath("title").asText())
        );*/
    }

}
