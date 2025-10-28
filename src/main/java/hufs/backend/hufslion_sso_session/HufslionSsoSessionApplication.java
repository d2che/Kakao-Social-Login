package hufs.backend.hufslion_sso_session;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class HufslionSsoSessionApplication {

	public static void main(String[] args) {
		SpringApplication.run(HufslionSsoSessionApplication.class, args);
	}

}
