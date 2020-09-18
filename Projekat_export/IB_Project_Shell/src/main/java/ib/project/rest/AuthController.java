package ib.project.rest;

import org.springframework.web.bind.annotation.RestController;
import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.security.authentication.AuthenticationManager;

import ib.project.model.Authority;
import ib.project.model.User;
import ib.project.service.AuthorityService;
import ib.project.service.LoggedUserService;
import ib.project.service.UserService;

@RestController
@RequestMapping(value = "/auth")

public class AuthController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private LoggedUserService loggedUserService;
	
	@Autowired
	private UserService userService;
}
