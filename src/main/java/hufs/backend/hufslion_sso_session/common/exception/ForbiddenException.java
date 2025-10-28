package hufs.backend.hufslion_sso_session.common.exception;

import org.springframework.http.HttpStatus;


public class ForbiddenException extends BaseException {

    public ForbiddenException() {
        super(HttpStatus.FORBIDDEN);
    }

    public ForbiddenException(String message) {
        super(HttpStatus.FORBIDDEN, message);
    }
}
