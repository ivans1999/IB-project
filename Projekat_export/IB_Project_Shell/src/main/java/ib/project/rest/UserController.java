package ib.project.rest;

import java.util.ArrayList;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import ib.project.certAndSignGen.CertReader;
import ib.project.model.Authority;
import ib.project.model.User;
import ib.project.service.AuthorityService;
import ib.project.service.UserService;

@RestController
@RequestMapping(value="api/users")
public class UserController {

	@Autowired
	public UserService userService;
	@Autowired
	public AuthorityService authorityService;
	
	
	@GetMapping(path="/")
	public ArrayList<User> findAll() {
		return userService.findAll();
	}
	
	@GetMapping(path="user/email")
	public ResponseEntity<User> userEmail(@RequestParam String email) {
		User user = userService.findByEmail(email);
		if (user != null) {
			return new ResponseEntity<User>(user,HttpStatus.OK);
		} else {
			System.out.println("User sa dati e-mailom nije pronadjen.");
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
	}
	
	@PostMapping(path="user/login")
	public ResponseEntity<User> loginUser(@RequestParam String email, @RequestParam String password) {
		User user = userService.findByEmailAndPassword(email, password);
		try {
			return new ResponseEntity<User>(user, HttpStatus.OK);
		} catch (Exception e) {
			System.out.println("User sa datim e-mailom i sifrom nije pronadjen.");
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
	}
	
	
	@PostMapping(path="user/register")
	public ResponseEntity<User> registrationUser(@RequestParam String email, @RequestParam String password) {
		Authority authority = authorityService.findByName("Regular");
		User user = new User();
		User userChecker = userService.findByEmail(email);
		if (userChecker == null) {
			user.setActive(false);
			user.setAuthority(authority);
			user.setCertificate("");
			user.setEmail(email);
			user.setPassword(password);
			
			userService.save(user);
			return new ResponseEntity<User>(user,HttpStatus.CREATED);
		}else {
			System.out.println("Uneli ste vec postojeci e-mail.");
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
	}
	
	@GetMapping(path = "/getKeyStorePath/{email}")
	public ResponseEntity<String> getKeyStorePath(@PathVariable("email") String email) {
		User user = userService.findByEmail(email);
		String path = "./data/" + user.getId() + ".jks";
		
		return new ResponseEntity<String>(path, HttpStatus.OK);
	}
	
	@GetMapping(path = "/downloadCertificate/{id}")
	public ResponseEntity<byte[]> downloadCertificate(@PathVariable("id") Long id) {

		Certificate certificate = CertReader.readBase64EncodedCertificate
				("./data/" + id + ".cer");
		
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.add("filename", id + ".cer");

		byte[] bFile = new byte[0];
		try {
			bFile = certificate.getEncoded();
			return ResponseEntity.ok().headers(headers).body(bFile);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}

		return new ResponseEntity<byte[]>(HttpStatus.BAD_REQUEST);
	}
	
	
}