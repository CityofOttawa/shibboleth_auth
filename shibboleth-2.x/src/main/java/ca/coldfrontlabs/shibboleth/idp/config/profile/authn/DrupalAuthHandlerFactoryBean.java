package ca.coldfrontlabs.shibboleth.idp.config.profile.authn;

import ca.coldfrontlabs.shibboleth.idp.authn.provider.DrupalAuthLoginHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;
/**
 * Factory bean for {@link DrupalAuthLoginHandler}s.
 */

public class DrupalAuthHandlerFactoryBean extends AbstractLoginHandlerFactoryBean{

    /** The URL of the login servlet. */
    private String authenticationServletURL;

    /** The name of the cookie to search for */
    private String authCookieName;

    /** The remote endpoint for validating sessions */
    private String authValidationEndpoint;

    /** The remote header containing client ip */
    private String xforwardedHeader;

    /** The drupal login URL */
    private String drupalLoginURL;

    /** Whether or not to validate the request ip and session ip */
    private Boolean validateSessionIP;

    /** Watch for these parameters in the auth request Referer header, and use them to infer a language for the authentication page */
    private String parseLangQueryParams;

    public String getAuthCookieName() {
        return authCookieName;
    }

    public void setAuthCookieName(String name) {
        authCookieName = name;
    }

    public String getAuthValidationEndpoint() {
        return authValidationEndpoint;
    }

    public void setAuthValidationEndpoint(String name) {
        authValidationEndpoint = name;
    }

    public String getAuthenticationServletURL() {
        return authenticationServletURL;
    }

    public void setAuthenticationServletURL(String name) {
        authenticationServletURL = name;
    }

    public String getDrupalLoginURL() {
        return drupalLoginURL;
    }

    public void setDrupalLoginURL(String name) {
        drupalLoginURL = name;
    }

    public void setXforwardedHeader(String header) {
        xforwardedHeader = header;
    }

    public String getXforwardedHeader() {
        return xforwardedHeader;
    }

    public void setValidateSessionIP(Boolean valid) {
        validateSessionIP = valid;
    }

    public Boolean getValidateSessionIP() {
        return validateSessionIP;
    }

    public void setParseLangQueryParams(String parseLangQueryParams) {
        this.parseLangQueryParams = parseLangQueryParams;
    }

    public String getParseLangQueryParams() {
        return parseLangQueryParams;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        DrupalAuthLoginHandler handler = new DrupalAuthLoginHandler(authenticationServletURL);
        handler.setAuthCookieName(getAuthCookieName());
        handler.setAuthValidationEndpoint(getAuthValidationEndpoint());
        handler.setDrupalLoginURL(getDrupalLoginURL());
        handler.setXforwardedHeader(getXforwardedHeader());
        handler.setValidateSessionIP(getValidateSessionIP());
        handler.setParseLangQueryParams(getParseLangQueryParams());
        populateHandler(handler);
        return handler;
    }

    @Override
    public Class getObjectType() {
        return DrupalAuthLoginHandler.class;
    }
}
