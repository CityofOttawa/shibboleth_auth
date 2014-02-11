package ca.coldfrontlabs.shibboleth.idp.authn;

public class AuthValidatorResult {
	public boolean valid = false;
	public String username = "";
	public String URI = "";

        public AuthValidatorResult()
        {
          this.valid = false;
        }

	public AuthValidatorResult(boolean valid)
	{
	  super();
	  this.valid = valid;
	}

        public AuthValidatorResult(boolean valid, String username)
        {
	  super();
	  this.valid = valid;
	  this.username = username;
	}

        public AuthValidatorResult(boolean valid, String username, String URI)
        {
	  super();
	  this.valid = valid;
	  this.username =  username;
	  this.URI = URI;
	}
}
