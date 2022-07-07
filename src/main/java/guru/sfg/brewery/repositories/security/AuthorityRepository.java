package guru.sfg.brewery.repositories.security;

import guru.sfg.brewery.domain.security.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<User, Integer> {
}
