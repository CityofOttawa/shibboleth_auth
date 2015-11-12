package ca.coldfrontlabs.shibboleth.idp.authn.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import org.opensaml.saml2.metadata.EntityDescriptor;

import ca.coldfrontlabs.shibboleth.idp.authn.DrupalAuthValidator;
import ca.coldfrontlabs.shibboleth.idp.authn.AuthValidatorResult;

public class DrupalAuthServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = 1745674094856635526L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DrupalAuthServlet.class);

    /** {@inheritDoc} */
    protected void service(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException, IOException
    {
      log.info("Starting DrupalAuth authentication");
      HttpSession session = httpRequest.getSession();
      String authCookieName = (String) session.getAttribute("drupalauth.authCookieName");
      String authValidationEndpoint = (String) session.getAttribute("drupalauth.authValidationEndpoint");
      String drupalLoginURL = (String) session.getAttribute("drupalauth.drupalLoginURL");
      String xforwardedHeader  = (String) session.getAttribute("drupalauth.xforwardedHeader");
      Boolean validateSessionIP  = (Boolean) session.getAttribute("drupalauth.validateSessionIP");
      String parseLangQueryParams  = (String) session.getAttribute("drupalauth.parseLangQueryParams");

      if (authCookieName == "" || authValidationEndpoint == "") {
        log.error("Missing critical settings");
        AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
      }

      // Grab the requesting SP and pass it to the auth service to enable extended checks on user profile
      // Snippet of code from Shibboleth.net
      ServletContext application = null;
      LoginContext loginContext = null;
      EntityDescriptor entityDescriptor = null;
      String entityID = null;
      try {
    	application = this.getServletContext();
	loginContext = HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application),application, httpRequest);
     	entityDescriptor = HttpServletHelper.getRelyingPartyMetadata(loginContext.getRelyingPartyId(),HttpServletHelper.getRelyingPartyConfirmationManager(application));
     	// the entityID value is the unique SP entityID, it can be used to trigger customization
        // of the login page
     	entityID = entityDescriptor.getEntityID();
	log.info("DrupalAuth entityID found: " + entityID);

      } catch (Exception e) {
     	log.error("Exception determining SP entityID");
     	if (application == null) {
         log.error("application is null");
     	}
     	if (loginContext == null) {
         log.error("loginContext is null");
     	}
     	if (entityDescriptor == null) {
         log.error("entityDescriptor is null");
     	}
      }

      String token = DrupalAuthValidator.resolveCookie(httpRequest, authCookieName);
      AuthValidatorResult results = null;

      if (token != "") {
        log.info("DrupalAuth Authentication found: " + token);
        results = DrupalAuthValidator.validateSession(httpRequest, token, entityID, authValidationEndpoint, xforwardedHeader, validateSessionIP, log);
      } else {
        log.info("No DrupalAuth cookie found.");
      }

      if (results != null && results.valid ) {
        log.info("Drupal Authentication Successful, username: " + results.username);
        httpRequest.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, results.username);
        AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
      } else {
        log.info("Drupal Authentication Failed");

        //  If the validator returned a redirect URL (missing user consent), use that
        if( results != null && results.URI != "" )
          drupalLoginURL = results.URI;

        // Append a lang string if we have one
        if (!parseLangQueryParams.isEmpty())
        {
          String inferredLang = InferLang(httpRequest, parseLangQueryParams);
          if (inferredLang != null)
          {
            log.debug("Inferred language is " + inferredLang);
            if (!drupalLoginURL.contains("?"))
              drupalLoginURL = drupalLoginURL + "?lang=" + inferredLang;
            else
              drupalLoginURL = drupalLoginURL + "&lang=" + inferredLang;
          }
        }

        log.debug("Redirecting to Drupal login page {}", drupalLoginURL);
        httpResponse.sendRedirect(drupalLoginURL);
      }
      return;
    }

    protected String InferLang(HttpServletRequest httpRequest, String parseLangQueryParams)
    {
      // Examine the referer header that came with this request to see if we can infer the user's language.
      // If we find a query string paramater that matches the list provided, return the content of that param.
      try
      {
        String referrer = httpRequest.getHeader("referer");
        if (referrer != null)
        {
          // These are the params we will look for
          String[] langParams = parseLangQueryParams.split(";");

          // Now parse the referrer URL
          URL referrerUrl = new URL(referrer);
          String[] params = referrerUrl.getQuery().split("&");
          for (String param : params)
          {
              int splitPos = param.indexOf("=");
              String paramName = URLDecoder.decode(param.substring(0, splitPos), "UTF-8");

              // If we find a matching lang param, return its value
              for (int i = 0; i < langParams.length; i++)
                if (paramName.equalsIgnoreCase(langParams[i]))
                  return URLDecoder.decode(param.substring(splitPos + 1), "UTF-8");
          }
        }
      }
      catch (Exception ex)
      {
        log.error("Unable to infer a lang parameter: " + ex.getMessage());
      }

      return null;
    }
}
