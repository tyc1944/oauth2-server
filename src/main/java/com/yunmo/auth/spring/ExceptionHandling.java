package com.yunmo.auth.spring;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.NativeWebRequest;
import org.zalando.problem.Problem;
import org.zalando.problem.Status;
import org.zalando.problem.StatusType;
import org.zalando.problem.spring.web.advice.ProblemHandling;
import org.zalando.problem.spring.web.advice.security.SecurityAdviceTrait;

import java.util.Optional;


@ControllerAdvice
public class ExceptionHandling implements ProblemHandling , SecurityAdviceTrait {

    @ExceptionHandler
    public ResponseEntity<Problem> handleEntityNotFound(
            final BadCredentialsException exception,
            final NativeWebRequest request) {
        return create(Status.UNAUTHORIZED, exception, request);
    }

    @ExceptionHandler
    public ResponseEntity<Problem> handleEntityNotFound(
            final DisabledException exception,
            final NativeWebRequest request) {
        return ResponseEntity.status(Status.UNAUTHORIZED.getStatusCode()).body(Problem.builder()
                .withDetail("账户已禁用")
                .withStatus(Status.UNAUTHORIZED)
                .withTitle(Status.UNAUTHORIZED.getReasonPhrase())
                .build());
    }

}
