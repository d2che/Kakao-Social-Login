package hufs.backend.hufslion_sso_session.common.exception;

import org.springframework.http.HttpStatus;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class BaseException extends RuntimeException {

    HttpStatus statusCode;
    String responseMessage;

    public BaseException(HttpStatus statusCode) {
        super();
        this.statusCode = statusCode;
    }

    public BaseException(HttpStatus statusCode, String responseMessage) {
        super();
        this.statusCode = statusCode;
        this.responseMessage = responseMessage;
    }

    public int getStatusCode() {
        return this.statusCode.value();
    }
}
