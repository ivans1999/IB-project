package ib.project.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import ib.project.model.Authority;
import ib.project.repository.AuthorityRepository;

@Service
public class AuthorityService implements AuthorityServiceInterface {
	
	@Autowired
	private AuthorityRepository authorityRepository;
	
	@Override
	public Authority findById (int id) {
		return authorityRepository.findById(id);
	}
	
	@Override
	public Authority findByName (String name) {
		return authorityRepository.findByName(name);
	}
}
