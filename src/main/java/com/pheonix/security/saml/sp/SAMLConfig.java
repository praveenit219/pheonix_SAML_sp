package com.pheonix.security.saml.sp;



import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.binding.decoding.HTTPArtifactDecoderImpl;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;

import com.pheonix.security.UpgradedSAMLBootstrap;
import com.pheonix.security.saml.api.SpConfiguration;

/**
 * Typically this should all be done by default convention in the Spring SAML library,
 * but as Spring SAML is not build with conventions over configuration we do all the
 * plumbing ourselves.
 */
@Configuration
public class SAMLConfig {

	@Autowired
	private Environment environment;

	@Bean
	public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
		
		MultiThreadedHttpConnectionManager connectionManager = new MultiThreadedHttpConnectionManager();
		 HttpConnectionManagerParams params = new HttpConnectionManagerParams();  
         params.setDefaultMaxConnectionsPerHost(5);  
         params.setMaxTotalConnections(50);  
         params.setConnectionTimeout(5000);  
         params.setSoTimeout(5000); 
         connectionManager.setParams(params);
		//connectionManager.getParams().setDefaultMaxConnectionsPerHost(10);
		//connectionManager.getParams().setMaxTotalConnections(50);
		
		
		return new MultiThreadedHttpConnectionManager();
	}

	@Bean
	public HttpClient httpClient() {
		return new HttpClient(multiThreadedHttpConnectionManager());
	}

	private HTTPArtifactBinding artifactBinding(ParserPool parserPool,
			VelocityEngine velocityEngine,ArtifactResolutionProfile resolutionProfile) {
		httpArtifactDecoder(resolutionProfile,parserPool,httpClient(),httpSOAP11Binding(parserPool));
		return new HTTPArtifactBinding(parserPool, velocityEngine, resolutionProfile);
	}


	@Bean
	public  HTTPArtifactDecoderImpl httpArtifactDecoder(ArtifactResolutionProfile resolutionProfile, ParserPool parserPool, HttpClient httpClient,HTTPSOAP11Binding httpSOAP11Binding) {
		

		return new HTTPArtifactDecoderImpl( resolutionProfile,parserPool); 
	}


	@Bean
	public HTTPArtifactBinding artifactBinding(HTTPSOAP11Binding httpSOAP11Binding,
			HttpClient httpClient,
			ParserPool parserPool,
			VelocityEngine velocityEngine) {
		ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient);
		// artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(httpSOAP11Binding));
		
		
		artifactResolutionProfile.setProcessor(new SAMLProcessorImpl( httpSOAP11Binding));
		
		artifactResolutionProfile.setMetadata(metadata);

		httpArtifactDecoder(artifactResolutionProfile,parserPool,httpClient,httpSOAP11Binding);

		return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile);
	}

	@Autowired
	private CachingMetadataManager metadata;

	@Bean
	@Autowired
	public HTTPSOAP11Binding soapBinding(ParserPool parserPool) {
		return new HTTPSOAP11Binding(parserPool);
	}

	@Bean
	@Autowired
	public HTTPPostBinding httpPostBinding(ParserPool parserPool, VelocityEngine velocityEngine, @Value("${sp.compare_endpoints}") boolean compareEndpoints) {
		HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");
		HTTPPostDecoder decoder = new HTTPPostDecoder(parserPool);
		if (!compareEndpoints) {
			decoder.setURIComparator((uri1, uri2) -> true);
		}
		return new HTTPPostBinding(parserPool, decoder, encoder);
	}

	@Bean
	@Autowired
	public HTTPRedirectDeflateBinding httpRedirectDeflateBinding(ParserPool parserPool) {

		return new HTTPRedirectDeflateBinding(parserPool);
	}

	@Bean
	@Autowired
	public HTTPSOAP11Binding httpSOAP11Binding(ParserPool parserPool) {
		return new HTTPSOAP11Binding(parserPool);
	}

	@Bean
	@Autowired
	public HTTPPAOS11Binding httpPAOS11Binding(ParserPool parserPool) {
		return new HTTPPAOS11Binding(parserPool);
	}


	private ArtifactResolutionProfile artifactResolutionProfile() {
		ArtifactResolutionProfileImpl artifactResolutionProfileImpl = new ArtifactResolutionProfileImpl(httpClient());
		artifactResolutionProfileImpl.setMetadata(metadata);
		return artifactResolutionProfileImpl;
	}

	


	@Bean
	public SAMLProcessorImpl processor(HTTPRedirectDeflateBinding httpRedirectDeflateBinding,
			HTTPPostBinding httpPostBinding,
			HTTPArtifactBinding httpArtifactBinding,
			HTTPSOAP11Binding httpSOAP11Binding,
			HTTPPAOS11Binding httpPAOS11Binding) {
		ArtifactResolutionProfileImpl artifactResolutionProfileImpl = new ArtifactResolutionProfileImpl(httpClient());
		artifactResolutionProfileImpl.setMetadata(metadata);
		
		Collection<SAMLBinding> bindings = new ArrayList<>();
		bindings.add(httpRedirectDeflateBinding);
		bindings.add(httpPostBinding);
		bindings.add(httpArtifactBinding);
		bindings.add(httpSOAP11Binding);
		bindings.add(httpPAOS11Binding);
		return new SAMLProcessorImpl(bindings);
	}

	@Autowired
	@Bean
	public SAMLProcessor processor(VelocityEngine velocityEngine,
			ParserPool parserPool,
			SpConfiguration spConfiguration,
			@Value("${sp.compare_endpoints}") boolean compareEndpoints) {
		ArtifactResolutionProfile artifactResolutionProfile =  artifactResolutionProfile();		 
		Collection<SAMLBinding> bindings = new ArrayList<>();
		bindings.add(httpRedirectDeflateBinding(parserPool));
		bindings.add(httpPostBinding(parserPool, velocityEngine, compareEndpoints));
		bindings.add(artifactBinding(parserPool, velocityEngine,artifactResolutionProfile));
		bindings.add(httpSOAP11Binding(parserPool));
		bindings.add(httpPAOS11Binding(parserPool));
		return new ConfigurableSAMLProcessor(bindings, spConfiguration);
	}

	@Bean
	public static SAMLBootstrap sAMLBootstrap() {
		return new UpgradedSAMLBootstrap();
	}

	@Bean
	public SAMLDefaultLogger samlLogger() {
		return new SAMLDefaultLogger();
	}

	@Bean
	public WebSSOProfileConsumer webSSOprofileConsumer() {
		WebSSOProfileConsumerImpl webSSOProfileConsumer = environment.acceptsProfiles("test") ?
				new WebSSOProfileConsumerImpl() {
			@Override
			@SuppressWarnings("unchecked")
			protected void verifyAssertion(Assertion assertion, AuthnRequest request, SAMLMessageContext context) throws AuthenticationException, SAMLException, org.opensaml.xml.security.SecurityException, ValidationException, DecryptionException {
				//nope
				context.setSubjectNameIdentifier(assertion.getSubject().getNameID());
			}
		} : new WebSSOProfileConsumerImpl();
		webSSOProfileConsumer.setResponseSkew(15 * 60);
		return webSSOProfileConsumer;
	}

	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
		return new WebSSOProfileConsumerHoKImpl();
	}

	@Bean
	@Autowired
	public WebSSOProfile webSSOprofile(SAMLProcessor samlProcessor) {
		WebSSOProfileImpl webSSOProfile = new WebSSOProfileImpl();
		webSSOProfile.setProcessor(samlProcessor);
		return webSSOProfile;
	}

	@Bean
	public WebSSOProfileECPImpl ecpprofile() {
		return new WebSSOProfileECPImpl();
	}

}
