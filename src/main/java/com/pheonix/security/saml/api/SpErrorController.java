package com.pheonix.security.saml.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ErrorAttributes;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pheonix.security.common.ErrorController;

@RestController
@RequestMapping("/error")
public class SpErrorController extends ErrorController {

  @Autowired
  public SpErrorController(ErrorAttributes errorAttributes) {
    super(errorAttributes);
  }
}
