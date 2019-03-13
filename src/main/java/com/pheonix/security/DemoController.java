package com.pheonix.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DemoController {

	@GetMapping("/demo")
	public String getValue() {
		return "hello working";
	}
}