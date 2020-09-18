package ib.project.auth;

public class JWTAuth {

	 private String username;
	 private String password;

	    public JWTAuth() {
	        super();
	    }

	    public JWTAuth(String username, String password) {
	        this.setUsername(username);
	        this.setPassword(password);
	    }

	    public String getUsername() {
	        return this.username;
	    }

	    public void setUsername(String username) {
	        this.username = username;
	    }

	    public String getPassword() {
	        return this.password;
	    }

	    public void setPassword(String password) {
	        this.password = password;
	    }
}
