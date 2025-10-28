package hufs.backend.hufslion_sso_session.common.entity;

import java.time.LocalDate;
import java.time.LocalDateTime;

import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import lombok.Getter;

@MappedSuperclass
@Getter
public class ExtendBaseTimeEntity extends BaseTimeEntity {

    protected LocalDate createdDate;

    @PrePersist
    protected void onPrePersist() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }

        this.createdDate = this.createdAt.toLocalDate();
    }
}
