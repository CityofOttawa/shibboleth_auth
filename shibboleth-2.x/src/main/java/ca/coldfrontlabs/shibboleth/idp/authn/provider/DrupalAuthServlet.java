package ca.coldfrontlabs.shibboleth.idp.authn.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.Cookie;

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

      authCookieName = authCookieName == null ? "" : authCookieName;
      authValidationEndpoint = authValidationEndpoint == null ? "" : authValidationEndpoint;
      drupalLoginURL = drupalLoginURL == null ? "" : drupalLoginURL;
      xforwardedHeader = xforwardedHeader == null ? "" : xforwardedHeader;
      validateSessionIP = validateSessionIP == null ? false : validateSessionIP;
      parseLangQueryParams = parseLangQueryParams == null ? "" : parseLangQueryParams;

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

        // If we can infere a prefered language from the client request, append
        // a lang param to the login/redirect page
        String preferredLang = GetPreferredLanguage(httpRequest, parseLangQueryParams);
        if (preferredLang != null)
        {
          String langParam = "lang=" + preferredLang;
          String queryStringAppendChar = "?";
          if (drupalLoginURL.contains("?"))
            queryStringAppendChar = "&"; // add to existing params instead
          drupalLoginURL += queryStringAppendChar + langParam;
        }

        log.debug("Redirecting to Drupal login page {}", drupalLoginURL);
        httpResponse.sendRedirect(drupalLoginURL);
      }
      return;
    }

    // Examines the user's request and tries to guess what language they prefer
    // Returns one of: null, "en", "fr"
    protected String GetPreferredLanguage(HttpServletRequest httpRequest, String parseLangQueryParams)
    {
      String preferredLang = null;

      // Attempt to detect a lang parameter in the referral URL
      preferredLang = InferLangFromReferralUrl(httpRequest, parseLangQueryParams);

      // If the cookie failed, retrieve the user's language preference from a shared cookie
      if (preferredLang == null)
        preferredLang = InferLangFromCookie(httpRequest);

      // If some kind of language string was found, coerce it into one of the
      // permitted values
      if (preferredLang != null)
      {
        preferredLang = preferredLang.trim().toLowerCase();
        if (!preferredLang.equals("fr"))
          preferredLang = "en";
      }

      log.debug("Preferred language is " + preferredLang == null ? "NULL" : preferredLang);
      return preferredLang;
    }

    protected String InferLangFromCookie(HttpServletRequest httpRequest)
    {
      // Try to locate a cookie that states the user's language preference.
      // Calling applications should use this name when setting the cookie.
      // Cookie name: "language-preference"
      // Permissible values: "fr" or "en"
      try
      {
        for (Cookie cookie : httpRequest.getCookies())
          if (cookie.getName().equals("language-preference"))
          {
            String lang = cookie.getValue();
            log.debug("Found language preference in cookie: " + lang);
            return lang;
          }
      }
      catch (Exception ex)
      {
        log.error("Unable to infer a lang parameter from cookie: " + ex.getMessage());
      }

      return null;
    }

    protected String InferLangFromReferralUrl(HttpServletRequest httpRequest, String parseLangQueryParams)
    {
      // Examine the referer header that came with this request to see if we can infer the user's language.
      // If we find a query string paramater that matches the list provided, return the content of that param.
      try
      {
        String referrer = httpRequest.getHeader("referer");
        if (referrer != null && !parseLangQueryParams.isEmpty())
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
                {
                  String lang = URLDecoder.decode(param.substring(splitPos + 1), "UTF-8");
                  log.debug("Found language preference in referral URL: " + lang);
                  return lang;
                }
          }
        }
      }
      catch (Exception ex)
      {
        log.error("Unable to infer a lang parameter from referral URL: " + ex.getMessage());
      }

      return null;
    }
}
