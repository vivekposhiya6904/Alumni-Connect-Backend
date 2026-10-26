package com.alumni.management.email;

import com.alumni.management.email.service.EmailService;
import com.alumni.management.verification.enums.VerificationPurpose;
import com.alumni.management.verification.exception.EmailDeliveryException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Flow;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailServiceTest {

    @Mock
    private HttpClient mockHttpClient;

    @Mock
    private HttpResponse<String> mockHttpResponse;

    private final String testApiKey = "re_mock_test_key_123456789";
    private final String testFromEmail = "onboarding@resend.dev";
    private final String testRecipient = "alumni@example.com";
    private final String testOtp = "654321";

    private EmailService createService(String apiKey, String fromEmail) {
        return new EmailService(apiKey, fromEmail, mockHttpClient);
    }

    @Test
    @DisplayName("Successful Resend API call (HTTP 200) dispatches email and validates payload structure")
    void testSendVerificationOtpEmail_Success() throws Exception {
        EmailService service = createService(testApiKey, testFromEmail);

        when(mockHttpResponse.statusCode()).thenReturn(200);
        doReturn(mockHttpResponse).when(mockHttpClient).send(any(HttpRequest.class), any());

        service.sendVerificationOtpEmail(testRecipient, testOtp, VerificationPurpose.ACCOUNT_REGISTRATION);

        ArgumentCaptor<HttpRequest> requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(mockHttpClient, times(1)).send(requestCaptor.capture(), any());

        HttpRequest sentRequest = requestCaptor.getValue();
        assertEquals(URI.create("https://api.resend.com/emails"), sentRequest.uri());
        assertEquals("POST", sentRequest.method());

        HttpHeaders headers = sentRequest.headers();
        assertEquals("Bearer " + testApiKey, headers.firstValue("Authorization").orElse(null));
        assertEquals("application/json", headers.firstValue("Content-Type").orElse(null));

        String body = extractRequestBody(sentRequest);
        assertTrue(body.contains("\"from\":\"GLS Connect <onboarding@resend.dev>\""));
        assertTrue(body.contains("\"to\":[\"" + testRecipient + "\"]"));
        assertTrue(body.contains("\"subject\":\"GLS Connect - Account Registration Verification\""));
        assertTrue(body.contains(testOtp));
        assertTrue(body.contains("5 minutes"));
    }

    @Test
    @DisplayName("Sender with pre-configured display name format is preserved")
    void testSender_WithExistingDisplayName() throws Exception {
        EmailService service = createService(testApiKey, "GLS University <verify@gls.edu.in>");

        when(mockHttpResponse.statusCode()).thenReturn(200);
        doReturn(mockHttpResponse).when(mockHttpClient).send(any(HttpRequest.class), any());

        service.sendVerificationOtpEmail(testRecipient, testOtp, VerificationPurpose.ACCOUNT_ACTIVATION);

        ArgumentCaptor<HttpRequest> requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(mockHttpClient).send(requestCaptor.capture(), any());

        String body = extractRequestBody(requestCaptor.getValue());
        assertTrue(body.contains("\"from\":\"GLS University <verify@gls.edu.in>\""));
        assertTrue(body.contains("\"subject\":\"GLS Connect - Account Activation Verification\""));
    }

    @Test
    @DisplayName("Non-2xx HTTP response from Resend throws EmailDeliveryException without exposing secrets")
    void testSendVerificationOtpEmail_Non2xxResponse() throws Exception {
        EmailService service = createService(testApiKey, testFromEmail);

        when(mockHttpResponse.statusCode()).thenReturn(403);
        when(mockHttpResponse.body()).thenReturn(
                "{\"message\":\"You can only send testing emails to your own email address.\",\"statusCode\":403}"
        );
        doReturn(mockHttpResponse).when(mockHttpClient).send(any(HttpRequest.class), any());

        EmailDeliveryException ex = assertThrows(EmailDeliveryException.class, () ->
                service.sendVerificationOtpEmail(testRecipient, testOtp, VerificationPurpose.ACCOUNT_REGISTRATION)
        );

        assertTrue(ex.getMessage().contains("You can only send testing emails"));
        assertFalse(ex.getMessage().contains(testApiKey));
    }

    @Test
    @DisplayName("Network timeout or connection failure throws EmailDeliveryException")
    void testSendVerificationOtpEmail_NetworkFailure() throws Exception {
        EmailService service = createService(testApiKey, testFromEmail);

        when(mockHttpClient.send(any(HttpRequest.class), any()))
                .thenThrow(new HttpTimeoutException("Connection timed out"));

        EmailDeliveryException ex = assertThrows(EmailDeliveryException.class, () ->
                service.sendVerificationOtpEmail(testRecipient, testOtp, VerificationPurpose.ACCOUNT_REGISTRATION)
        );

        assertTrue(ex.getMessage().contains("network error"));
        assertFalse(ex.getMessage().contains(testApiKey));
    }

    @Test
    @DisplayName("Missing or blank RESEND_API_KEY throws descriptive EmailDeliveryException")
    void testMissingApiKey_ThrowsException() {
        EmailService service = createService("", testFromEmail);

        EmailDeliveryException ex = assertThrows(EmailDeliveryException.class, () ->
                service.sendVerificationOtpEmail(testRecipient, testOtp, VerificationPurpose.ACCOUNT_REGISTRATION)
        );

        assertTrue(ex.getMessage().contains("RESEND_API_KEY"));
        verifyNoInteractions(mockHttpClient);
    }

    @Test
    @DisplayName("Missing or blank RESEND_FROM_EMAIL throws descriptive EmailDeliveryException")
    void testMissingFromEmail_ThrowsException() {
        EmailService service = createService(testApiKey, "   ");

        EmailDeliveryException ex = assertThrows(EmailDeliveryException.class, () ->
                service.sendVerificationOtpEmail(testRecipient, testOtp, VerificationPurpose.ACCOUNT_REGISTRATION)
        );

        assertTrue(ex.getMessage().contains("RESEND_FROM_EMAIL"));
        verifyNoInteractions(mockHttpClient);
    }

    @Test
    @DisplayName("Missing or null recipient email throws EmailDeliveryException")
    void testMissingRecipient_ThrowsException() {
        EmailService service = createService(testApiKey, testFromEmail);

        EmailDeliveryException ex = assertThrows(EmailDeliveryException.class, () ->
                service.sendVerificationOtpEmail("", testOtp, VerificationPurpose.ACCOUNT_REGISTRATION)
        );

        assertTrue(ex.getMessage().contains("Recipient email address is required"));
        verifyNoInteractions(mockHttpClient);
    }

    @Test
    @DisplayName("sendOtpEmail for password reset preserves backward-compatible error handling")
    void testSendOtpEmail_PasswordReset() throws Exception {
        EmailService service = createService(testApiKey, testFromEmail);

        when(mockHttpResponse.statusCode()).thenReturn(200);
        doReturn(mockHttpResponse).when(mockHttpClient).send(any(HttpRequest.class), any());

        service.sendOtpEmail(testRecipient, testOtp);

        ArgumentCaptor<HttpRequest> requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(mockHttpClient).send(requestCaptor.capture(), any());

        String body = extractRequestBody(requestCaptor.getValue());
        assertTrue(body.contains("\"subject\":\"GLS Connect - Password Reset OTP\""));
        assertTrue(body.contains("15 minutes"));
        assertTrue(body.contains(testOtp));
    }

    @Test
    @DisplayName("sendOtpEmail catches failure without throwing exception to maintain caller contract")
    void testSendOtpEmail_FailureSuppression() throws Exception {
        EmailService service = createService(testApiKey, testFromEmail);

        when(mockHttpClient.send(any(HttpRequest.class), any()))
                .thenThrow(new IOException("Service unavailable"));

        assertDoesNotThrow(() -> service.sendOtpEmail(testRecipient, testOtp));
    }

    private String extractRequestBody(HttpRequest request) {
        if (request.bodyPublisher().isEmpty()) {
            return "";
        }
        var subscriber = new StringSubscriber();
        request.bodyPublisher().get().subscribe(subscriber);
        return subscriber.getBody();
    }

    private static class StringSubscriber implements Flow.Subscriber<ByteBuffer> {
        private final StringBuilder sb = new StringBuilder();

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(ByteBuffer item) {
            sb.append(StandardCharsets.UTF_8.decode(item));
        }

        @Override
        public void onError(Throwable throwable) {}

        @Override
        public void onComplete() {}

        public String getBody() {
            return sb.toString();
        }
    }
}
