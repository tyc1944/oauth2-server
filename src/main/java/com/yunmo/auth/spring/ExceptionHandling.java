package com.yunmo.auth.spring;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.NativeWebRequest;
import org.zalando.problem.Problem;
import org.zalando.problem.Status;
import org.zalando.problem.spring.web.advice.ProblemHandling;


@ControllerAdvice
public class ExceptionHandling implements ProblemHandling {
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Problem> handleEntityNotFound(
            final BadCredentialsException exception,
            final NativeWebRequest request) {
        return create(Status.UNAUTHORIZED, exception, request);
    }
}
